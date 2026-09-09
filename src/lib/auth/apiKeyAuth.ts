import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { isMongoActive, connectToDatabase } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { ApiKey } from '@/models/ApiKey';
import { Organization } from '@/models/Organization';

export class ApiKeyRateLimiter {
  private keyRequests: Map<string, number[]> = new Map();
  private defaultLimit: number = 60; // 60 requests per minute

  constructor(limit: number = 60) {
    this.defaultLimit = limit;
  }

  setLimit(limit: number): void {
    this.defaultLimit = limit;
  }

  checkRateLimit(
    keyId: string,
    limit: number = this.defaultLimit
  ): { allowed: boolean; limit: number; remaining: number; resetSeconds: number } {
    const now = Date.now();
    const windowStart = now - 60 * 1000;

    let timestamps = this.keyRequests.get(keyId) || [];
    timestamps = timestamps.filter((t) => t > windowStart);

    const resetSeconds = timestamps.length > 0
      ? Math.max(1, Math.ceil((timestamps[0] + 60 * 1000 - now) / 1000))
      : 60;

    if (timestamps.length >= limit) {
      this.keyRequests.set(keyId, timestamps);
      return {
        allowed: false,
        limit,
        remaining: 0,
        resetSeconds,
      };
    }

    timestamps.push(now);
    this.keyRequests.set(keyId, timestamps);

    return {
      allowed: true,
      limit,
      remaining: Math.max(0, limit - timestamps.length),
      resetSeconds,
    };
  }

  resetForTesting(): void {
    this.keyRequests.clear();
  }
}

export const apiKeyRateLimiter = new ApiKeyRateLimiter();

export interface ApiKeyAuthContext {
  organization: any;
  apiKey: any;
  rateLimit: {
    limit: number;
    remaining: number;
    resetSeconds: number;
  };
}

export class ApiAuthError extends Error {
  status: number;
  code: string;
  headers?: Record<string, string>;

  constructor(code: string, message: string, status: number = 401, headers?: Record<string, string>) {
    super(message);
    this.name = 'ApiAuthError';
    this.code = code;
    this.status = status;
    this.headers = headers;
  }
}

/**
 * Validates external API requests authenticated via API keys.
 * Enforces key validity, active state, expiration, tenant scoping, and independent rate limits.
 */
export async function requireApiKeyAuth(request: NextRequest): Promise<ApiKeyAuthContext> {
  const authHeader = request.headers.get('authorization');
  const apiKeyHeader = request.headers.get('x-api-key');

  let rawKey: string | null = null;
  if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
    rawKey = authHeader.substring(7).trim();
  } else if (apiKeyHeader) {
    rawKey = apiKeyHeader.trim();
  }

  if (!rawKey) {
    throw new ApiAuthError(
      'UNAUTHORIZED',
      'API key missing. Provide your key via "Authorization: Bearer <apiKey>" or "X-API-Key: <apiKey>".',
      401
    );
  }

  const hashedKey = crypto.createHash('sha256').update(rawKey).digest('hex');

  await connectToDatabase();
  let keyDoc: any = null;

  if (isMongoActive()) {
    keyDoc = await ApiKey.findOne({ hashedKey });
  } else {
    keyDoc =
      memoryStore.apiKeys.get(hashedKey) ||
      Array.from(memoryStore.apiKeys.values()).find(
        (k: any) => k.hashedKey === hashedKey || k.keyHash === hashedKey
      );
  }

  if (!keyDoc) {
    throw new ApiAuthError('INVALID_API_KEY', 'The provided API key is invalid or does not exist.', 401);
  }

  // Check if active or revoked
  if (keyDoc.active === false || keyDoc.revoked === true) {
    throw new ApiAuthError('API_KEY_REVOKED', 'This API key has been revoked.', 401);
  }

  // Check expiration
  if (keyDoc.expiresAt && new Date(keyDoc.expiresAt).getTime() < Date.now()) {
    throw new ApiAuthError('API_KEY_EXPIRED', 'This API key has expired.', 401);
  }

  // Resolve owning organization
  const orgIdStr = keyDoc.organizationId.toString();
  let org: any = null;

  if (isMongoActive()) {
    org = await Organization.findById(keyDoc.organizationId);
  } else {
    org = memoryStore.organizations.get(orgIdStr);
  }

  if (!org) {
    throw new ApiAuthError('ORGANIZATION_NOT_FOUND', 'Organization associated with this API key was not found.', 404);
  }

  const keyIdStr = (keyDoc._id || keyDoc.id).toString();

  // Enforce tier-based rate limiting per API key (§A.5 & §5)
  const { getApiRateLimit } = await import('@/lib/billing/plans');
  const tierLimit = getApiRateLimit(org.plan || 'FREE');
  const rateLimit = apiKeyRateLimiter.checkRateLimit(keyIdStr, tierLimit);
  if (!rateLimit.allowed) {
    throw new ApiAuthError(
      'RATE_LIMIT_EXCEEDED',
      `API key rate limit of ${rateLimit.limit} req/min exceeded for your ${org.plan || 'current'} plan. Please retry after ${rateLimit.resetSeconds} seconds.`,
      429,
      {
        'Retry-After': rateLimit.resetSeconds.toString(),
        'X-RateLimit-Limit': rateLimit.limit.toString(),
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': rateLimit.resetSeconds.toString(),
      }
    );
  }

  // Update lastUsedAt asynchronously
  keyDoc.lastUsedAt = new Date();
  if (isMongoActive()) {
    await keyDoc.save().catch(() => {});
  } else {
    memoryStore.apiKeys.set(hashedKey, keyDoc);
  }

  return {
    organization: org,
    apiKey: keyDoc,
    rateLimit: {
      limit: rateLimit.limit,
      remaining: rateLimit.remaining,
      resetSeconds: rateLimit.resetSeconds,
    },
  };
}

/**
 * Formats standardized API response envelopes for all /api/v1/* endpoints.
 */
export function formatApiResponse(
  data: any,
  meta?: Record<string, any>,
  rateLimitHeaders?: Record<string, string>
) {
  const headers = new Headers({
    'Content-Type': 'application/json',
    ...(rateLimitHeaders || {}),
  });

  return NextResponse.json(
    {
      success: true,
      data,
      ...(meta ? { meta } : {}),
    },
    { status: 200, headers }
  );
}

/**
 * Formats standardized API error envelopes for all /api/v1/* endpoints.
 */
export function formatApiErrorResponse(error: any) {
  const status = error.status || 500;
  const code = error.code || 'INTERNAL_SERVER_ERROR';
  const message = error.message || 'An unexpected error occurred';

  const headers = new Headers({
    'Content-Type': 'application/json',
    ...(error.headers || {}),
  });

  return NextResponse.json(
    {
      success: false,
      error: {
        code,
        message,
      },
    },
    { status, headers }
  );
}
