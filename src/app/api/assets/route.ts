import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { requireAuth } from '@/lib/auth';
import { Asset } from '@/models/Asset';
import { AuditLog } from '@/models/AuditLog';
import { generateVerificationToken } from '@/lib/verification';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';

const addAssetSchema = z.object({
  domain: z
    .string()
    .trim()
    .toLowerCase()
    .regex(/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/, {
      message: 'Must be a valid fully-qualified domain name (e.g., acme.com)',
    }),
  importance: z.enum(['CRITICAL', 'HIGH', 'NORMAL', 'LOW']).default('NORMAL'),
});

export async function GET(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request);
    const { searchParams } = new URL(request.url);
    const typeFilter = searchParams.get('type');
    const statusFilter = searchParams.get('status');
    const methodFilter = searchParams.get('discoveredVia');

    if (isMongoActive()) {
      const query: Record<string, any> = { organizationId: org._id };
      if (typeFilter) query.type = typeFilter;
      if (statusFilter) query.verificationStatus = statusFilter;
      if (methodFilter) query.discoveredVia = methodFilter;

      const assets = await Asset.find(query).sort({ createdAt: -1 });
      return NextResponse.json({ success: true, data: assets });
    }

    // In-memory fallback
    let assets = Array.from(memoryStore.assets.values()).filter(
      (a) => a.organizationId.toString() === org._id.toString()
    );
    if (typeFilter) assets = assets.filter((a) => a.type === typeFilter);
    if (statusFilter) assets = assets.filter((a) => a.verificationStatus === statusFilter);
    if (methodFilter) assets = assets.filter((a) => a.discoveredVia?.includes(methodFilter));

    assets.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    return NextResponse.json({ success: true, data: assets });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'ASSET_LIST_ERROR', message: error.message } },
      { status }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request);

    // Permission check: Viewers and agency delegates are strictly read-only (§1, §6)
    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === org._id?.toString()
    );
    const role = membership?.role || user.role || 'VIEWER';

    if (role === 'VIEWER' || user.isAgencyDelegate) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INSUFFICIENT_PERMISSIONS',
            message: 'Viewer or agency delegate role has read-only access and cannot add assets.',
          },
        },
        { status: 403 }
      );
    }

    const body = await request.json();

    const parseResult = addAssetSchema.safeParse(body);
    if (!parseResult.success) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'VALIDATION_FAILED',
            message: parseResult.error.errors.map((e) => e.message).join(', '),
          },
        },
        { status: 400 }
      );
    }

    const { domain, importance } = parseResult.data;

    // Quota validation
    let existingCount = 0;
    if (isMongoActive()) {
      existingCount = await Asset.countDocuments({
        organizationId: org._id,
        type: 'ROOT_DOMAIN',
      });
    } else {
      existingCount = Array.from(memoryStore.assets.values()).filter(
        (a) => a.organizationId.toString() === org._id.toString() && a.type === 'ROOT_DOMAIN'
      ).length;
    }

    const maxMonitored = org.scanQuotas?.maxMonitoredDomains ?? 50;
    if (existingCount >= maxMonitored) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'QUOTA_EXCEEDED',
            message: `Your ${org.plan || 'current'} plan is limited to ${maxMonitored} monitored root domains.`,
          },
        },
        { status: 403 }
      );
    }

    // Duplicate check
    let alreadyExists = false;
    if (isMongoActive()) {
      const found = await Asset.findOne({ organizationId: org._id, fqdn: domain });
      if (found) alreadyExists = true;
    } else {
      alreadyExists = Array.from(memoryStore.assets.values()).some(
        (a) => a.organizationId.toString() === org._id.toString() && a.fqdn === domain
      );
    }

    if (alreadyExists) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'ALREADY_EXISTS',
            message: `Domain ${domain} is already registered in your asset inventory.`,
          },
        },
        { status: 409 }
      );
    }

    const verificationToken = generateVerificationToken();

    let newAsset: any;
    if (isMongoActive()) {
      newAsset = await Asset.create({
        organizationId: org._id,
        rootDomain: domain,
        fqdn: domain,
        type: 'ROOT_DOMAIN',
        importance: importance || 'HIGH',
        verificationStatus: 'PENDING',
        verificationToken,
        ipAddresses: [],
        tags: ['production'],
      });

      await AuditLog.create({
        organizationId: org._id,
        actorId: user._id.toString(),
        action: 'DOMAIN_ADDED',
        objectType: 'Asset',
        objectId: newAsset._id.toString(),
        result: 'SUCCESS',
        details: { domain, verificationStatus: 'PENDING' },
      });
    } else {
      const assetId = `asset-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
      newAsset = {
        _id: assetId,
        organizationId: org._id,
        rootDomain: domain,
        fqdn: domain,
        type: 'ROOT_DOMAIN',
        importance: importance || 'HIGH',
        verificationStatus: 'PENDING',
        verificationToken,
        discoveredVia: ['MANUAL'],
        ipAddresses: [],
        tags: ['production'],
        firstSeen: new Date(),
        lastSeen: new Date(),
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      memoryStore.assets.set(assetId, newAsset);
      memoryStore.auditLogs.push({
        organizationId: org._id,
        actorId: user._id.toString(),
        action: 'DOMAIN_ADDED',
        objectType: 'Asset',
        objectId: assetId,
        result: 'SUCCESS',
        details: { domain, verificationStatus: 'PENDING' },
        createdAt: new Date(),
      });
    }

    return NextResponse.json({ success: true, data: newAsset }, { status: 201 });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'ASSET_CREATE_ERROR', message: error.message } },
      { status }
    );
  }
}
