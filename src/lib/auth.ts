import crypto from 'crypto';
import { NextRequest } from 'next/server';
import { env } from './env';
import { connectToDatabase, isMongoActive } from './db';
import { User } from '@/models/User';
import { Organization } from '@/models/Organization';
import { ApiKey } from '@/models/ApiKey';
import { AgencyClientLink } from '@/models/AgencyClientLink';
import { AuditLog } from '@/models/AuditLog';
import { memoryStore } from './store';

export const SESSION_COOKIE_NAME = 'pliora_session';

export interface SessionPayload {
  userId: string;
  email: string;
  organizationId: string;
  role: string;
  iat: number;
  exp: number;
}

/**
 * Hashes a plaintext password using crypto.scrypt with a unique cryptographically random salt.
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16).toString('hex');
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(`${salt}:${derivedKey.toString('hex')}`);
    });
  });
}

/**
 * Validates a plaintext password against a stored scrypt salt:key hash using timing-safe comparison.
 */
export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  if (!storedHash || !storedHash.includes(':')) return false;
  const [salt, keyHex] = storedHash.split(':');
  if (!salt || !keyHex) return false;

  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      try {
        const storedKeyBuf = Buffer.from(keyHex, 'hex');
        if (storedKeyBuf.length !== derivedKey.length) {
          return resolve(false);
        }
        resolve(crypto.timingSafeEqual(storedKeyBuf, derivedKey));
      } catch {
        resolve(false);
      }
    });
  });
}

function base64UrlEncode(str: string): string {
  return Buffer.from(str)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf8');
}

/**
 * Creates a cryptographically signed HMAC-SHA256 session token (standard JWT format).
 */
export function createSessionToken(
  payload: Omit<SessionPayload, 'iat' | 'exp'>,
  expiresInSeconds: number = 7 * 24 * 60 * 60 // 7 days
): string {
  const now = Math.floor(Date.now() / 1000);
  const fullPayload: SessionPayload = {
    ...payload,
    iat: now,
    exp: now + expiresInSeconds,
  };

  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));

  const signature = crypto
    .createHmac('sha256', env.JWT_SECRET)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

/**
 * Verifies and decodes a signed HMAC-SHA256 session token.
 */
export function verifySessionToken(token: string): SessionPayload | null {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [encodedHeader, encodedPayload, signature] = parts;

  const expectedSignature = crypto
    .createHmac('sha256', env.JWT_SECRET)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  const sigBuffer = Buffer.from(signature);
  const expectedSigBuffer = Buffer.from(expectedSignature);

  if (
    sigBuffer.length !== expectedSigBuffer.length ||
    !crypto.timingSafeEqual(sigBuffer, expectedSigBuffer)
  ) {
    return null;
  }

  try {
    const payload: SessionPayload = JSON.parse(base64UrlDecode(encodedPayload));
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return null; // Expired
    }
    return payload;
  } catch {
    return null;
  }
}

/**
 * Extracts session from request (Cookie or Bearer header).
 */
export async function getAuthenticatedSession(
  request: NextRequest
): Promise<{ user: any; organization: any } | null> {
  // 0. Check API Key header (x-api-key or Authorization: Bearer plk_live_...) (§A.5)
  const apiKeyHeader = request.headers.get('x-api-key');
  const authHeader = request.headers.get('authorization');
  let apiKeySecret: string | null = apiKeyHeader ? apiKeyHeader.trim() : null;

  if (!apiKeySecret && authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
    const candidate = authHeader.substring(7).trim();
    if (candidate.startsWith('plk_live_')) {
      apiKeySecret = candidate;
    }
  }

  if (apiKeySecret) {
    await connectToDatabase();
    const hashedKey = crypto.createHash('sha256').update(apiKeySecret).digest('hex');
    let keyDoc: any = null;

    if (isMongoActive()) {
      keyDoc = await ApiKey.findOne({ hashedKey });
    } else {
      keyDoc = memoryStore.apiKeys.get(hashedKey);
    }

    if (keyDoc) {
      if (keyDoc.expiresAt && new Date(keyDoc.expiresAt) < new Date()) {
        return null;
      }

      keyDoc.lastUsedAt = new Date();
      if (isMongoActive()) {
        await keyDoc.save().catch(() => {});
      } else {
        memoryStore.apiKeys.set(hashedKey, keyDoc);
      }

      let org: any = null;
      if (isMongoActive()) {
        org = await Organization.findById(keyDoc.organizationId);
      } else {
        org = memoryStore.organizations.get(keyDoc.organizationId.toString());
      }

      if (org) {
        const virtualUser = {
          _id: `key_${keyDoc._id || keyDoc.id}`,
          id: `key_${keyDoc._id || keyDoc.id}`,
          name: keyDoc.name || 'API Key',
          email: `apikey-${keyDoc.keyPrefix || 'key'}@pliora.internal`,
          role: keyDoc.role || 'VIEWER',
          isApiKey: true,
          activeOrganizationId: org._id || org.id,
          organizationMemberships: [
            {
              organizationId: org._id || org.id,
              role: keyDoc.role || 'VIEWER',
              joinedAt: keyDoc.createdAt,
            },
          ],
        };
        return await resolveAgencyDelegatedSession({ user: virtualUser, organization: org }, request);
      }
    }
    return null;
  }

  let token: string | null = null;

  // 1. Check HTTP-only cookie
  const cookie = request.cookies.get(SESSION_COOKIE_NAME);
  if (cookie?.value) {
    token = cookie.value;
  }

  // 2. Check Authorization Bearer header
  if (!token) {
    if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
      token = authHeader.substring(7).trim();
    }
  }

  if (!token) {
    return null;
  }

  const payload = verifySessionToken(token);
  if (!payload) {
    return null;
  }

  await connectToDatabase();

  let user: any = null;
  let organization: any = null;

  if (isMongoActive()) {
    user = await User.findById(payload.userId);
    organization = await Organization.findById(payload.organizationId);
  } else {
    user = memoryStore.users.get(payload.userId);
    organization = memoryStore.organizations.get(payload.organizationId);

    // If user or org not in memory store, synthesize from verified cryptographic JWT payload
    if (!user && payload.userId && payload.organizationId) {
      user = {
        _id: payload.userId,
        email: payload.email,
        organizationMemberships: [
          {
            organizationId: payload.organizationId,
            role: payload.role || 'VIEWER',
          },
        ],
        activeOrganizationId: payload.organizationId,
      };
    }
    if (!organization && payload.organizationId) {
      organization = {
        _id: payload.organizationId,
        name: 'Organization',
        slug: `org-${payload.organizationId}`,
        plan: 'PRO',
        scanQuotas: {
          maxMonitoredDomains: 50,
          dailyScanLimit: 500,
          concurrentScans: 10,
        },
      };
    }
  }

  if (!user || !organization) {
    return null;
  }

  return await resolveAgencyDelegatedSession({ user, organization }, request);
}

/**
 * Handles cross-tenant agency delegation (§1, §2, §6).
 * If x-client-org-id header or clientOrgId query param is specified, verifies
 * that caller organization is an AGENCY with an ACTIVE AgencyClientLink to the client.
 * Enforces strict read-only VIEWER role and records dual AuditLog entries on both orgs.
 */
async function resolveAgencyDelegatedSession(
  session: { user: any; organization: any },
  request: NextRequest
): Promise<{ user: any; organization: any }> {
  const { user, organization } = session;

  const clientOrgHeader = request.headers.get('x-client-org-id');
  let clientOrgQuery: string | null = null;
  try {
    const urlObj = request.nextUrl || new URL(request.url, 'http://localhost');
    clientOrgQuery = urlObj.searchParams?.get('clientOrgId');
  } catch {}

  const targetClientOrgId = (clientOrgHeader?.trim() || clientOrgQuery?.trim());
  const currentOrgId = (organization._id || organization.id)?.toString();

  if (!targetClientOrgId || targetClientOrgId === currentOrgId || targetClientOrgId === organization.slug) {
    return session;
  }

  // Caller is attempting cross-organization delegation
  // 1. Caller organization MUST be an agency (§2)
  if (organization.accountType !== 'AGENCY') {
    const err: any = new Error('Forbidden: Only agency accounts can delegate access into client organizations.');
    err.status = 403;
    throw err;
  }

  // 2. Look for an ACTIVE AgencyClientLink (§1, §6)
  await connectToDatabase();
  let link: any = null;

  if (isMongoActive()) {
    link = await AgencyClientLink.findOne({
      agencyOrgId: organization._id,
      $or: [
        { clientOrgId: targetClientOrgId },
        { 'clientOrgId._id': targetClientOrgId },
      ],
      status: 'ACTIVE',
    });

    if (!link) {
      const targetOrg = await Organization.findOne({ slug: targetClientOrgId });
      if (targetOrg) {
        link = await AgencyClientLink.findOne({
          agencyOrgId: organization._id,
          clientOrgId: targetOrg._id,
          status: 'ACTIVE',
        });
      }
    }
  } else {
    const links = Array.from(memoryStore.agencyClientLinks.values());
    link = links.find((l: any) => {
      const matchAgency = (l.agencyOrgId?.toString() === currentOrgId || l.agencyOrgId === currentOrgId);
      const matchClient = (l.clientOrgId?.toString() === targetClientOrgId || l.clientOrgId === targetClientOrgId);
      return matchAgency && matchClient && l.status === 'ACTIVE';
    });

    if (!link) {
      const targetOrg = Array.from(memoryStore.organizations.values()).find(
        (o: any) => o.slug === targetClientOrgId
      );
      if (targetOrg) {
        const targetId = (targetOrg._id || targetOrg.id)?.toString();
        link = links.find((l: any) => {
          const matchAgency = (l.agencyOrgId?.toString() === currentOrgId || l.agencyOrgId === currentOrgId);
          const matchClient = (l.clientOrgId?.toString() === targetId || l.clientOrgId === targetId);
          return matchAgency && matchClient && l.status === 'ACTIVE';
        });
      }
    }
  }

  if (!link) {
    const err: any = new Error('Forbidden: No active agency link to this client organization.');
    err.status = 403;
    throw err;
  }

  // 3. Resolve target client organization document
  let clientOrg: any = null;
  const resolvedClientOrgId = (link.clientOrgId?._id || link.clientOrgId)?.toString();

  if (isMongoActive()) {
    clientOrg = await Organization.findById(resolvedClientOrgId);
    if (!clientOrg && targetClientOrgId) {
      clientOrg = await Organization.findOne({ slug: targetClientOrgId });
    }
  } else {
    clientOrg = memoryStore.organizations.get(resolvedClientOrgId);
    if (!clientOrg) {
      clientOrg = Array.from(memoryStore.organizations.values()).find(
        (o: any) => (o._id || o.id)?.toString() === resolvedClientOrgId || o.slug === targetClientOrgId
      );
    }
  }

  if (!clientOrg) {
    const err: any = new Error('Not Found: Client organization not found.');
    err.status = 404;
    throw err;
  }

  // 4. Record Dual AuditLog entries (§2, §6)
  let reqPath = '/';
  try {
    reqPath = (request.nextUrl || new URL(request.url, 'http://localhost')).pathname;
  } catch {}

  const clientOrgIdStr = (clientOrg._id || clientOrg.id).toString();
  const agencyOrgIdStr = currentOrgId;
  const actorEmail = user.email || `agency-user-${user._id || user.id}`;

  const clientLogEntry = {
    organizationId: clientOrg._id || clientOrg.id,
    actorId: actorEmail,
    action: 'AGENCY_DATA_ACCESSED',
    objectType: 'ORGANIZATION',
    objectId: clientOrgIdStr,
    result: 'SUCCESS',
    details: {
      agencyOrgId: agencyOrgIdStr,
      agencyName: organization.name,
      agencyUserId: (user._id || user.id).toString(),
      agencyUserEmail: user.email,
      path: reqPath,
      scopes: link.scopes || ['READ_ONLY'],
      delegateBranding: Boolean(link.delegateBranding),
    },
    createdAt: new Date(),
  };

  const agencyLogEntry = {
    organizationId: organization._id || organization.id,
    actorId: actorEmail,
    action: 'AGENCY_CLIENT_ACCESSED',
    objectType: 'ORGANIZATION',
    objectId: clientOrgIdStr,
    result: 'SUCCESS',
    details: {
      clientOrgId: clientOrgIdStr,
      clientName: clientOrg.name,
      path: reqPath,
    },
    createdAt: new Date(),
  };

  if (isMongoActive()) {
    await AuditLog.create(clientLogEntry).catch(() => {});
    await AuditLog.create(agencyLogEntry).catch(() => {});
  } else {
    memoryStore.auditLogs.push(clientLogEntry);
    memoryStore.auditLogs.push(agencyLogEntry);
  }

  // 5. Construct virtual delegate user session with strict VIEWER role (§1, §6)
  const virtualDelegateUser = {
    ...user,
    role: 'VIEWER',
    isAgencyDelegate: true,
    agencyOrgId: agencyOrgIdStr,
    agencyUserId: (user._id || user.id).toString(),
    activeOrganizationId: clientOrgIdStr,
    organizationMemberships: [
      {
        organizationId: clientOrgIdStr,
        role: 'VIEWER',
        joinedAt: link.grantedAt || link.createdAt || new Date(),
      },
    ],
  };

  return { user: virtualDelegateUser, organization: clientOrg };
}

/**
 * Enforces authentication on API routes.
 * Throws an Error with 401 status if not authenticated.
 * In development mode without an explicit session, safely falls back to seeded demo org if enabled.
 */
export async function requireAuth(
  request: NextRequest,
  options?: { allowDevDemoFallback?: boolean }
): Promise<{ user: any; organization: any }> {
  const session = await getAuthenticatedSession(request);
  if (session) {
    return session;
  }

  // Dev demo fallback: only when explicitly requested, never when auth token was provided
  const hasToken = Boolean(request.cookies.get(SESSION_COOKIE_NAME) || request.headers.get('authorization'));
  const allowDev = !hasToken && (options?.allowDevDemoFallback ?? (env.NODE_ENV === 'development'));
  if (allowDev) {
    await connectToDatabase();
    let org: any;
    let user: any;

    if (isMongoActive()) {
      org = await Organization.findOne({ slug: 'acme-corp' });
      user = await User.findOne({ email: 'demo@pliora.io' });
    } else {
      org = memoryStore.organizations.get('acme-corp');
      user = memoryStore.users.get('demo-user-001');
    }

    if (org && user) {
      return await resolveAgencyDelegatedSession({ user, organization: org }, request);
    }
  }

  const err: any = new Error('Unauthorized: Authentication required.');
  err.status = 401;
  throw err;
}
