import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { requireAuth } from '@/lib/auth';
import { Asset } from '@/models/Asset';
import { Finding } from '@/models/Finding';
import { AuditLog } from '@/models/AuditLog';
import { generateVerificationToken } from '@/lib/verification';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { computeOrgRiskScore, recordRiskScoreSnapshot } from '@/lib/risk/orgScore';

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

export async function DELETE(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request);

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
            message: 'Viewer or agency delegate role cannot delete assets.',
          },
        },
        { status: 403 }
      );
    }

    const { searchParams } = new URL(request.url);
    let id = searchParams.get('id');

    if (!id) {
      const body = await request.json().catch(() => ({}));
      id = body?.id || body?.assetId;
    }

    if (!id) {
      return NextResponse.json(
        { success: false, error: { code: 'MISSING_ID', message: 'Asset id is required for deletion.' } },
        { status: 400 }
      );
    }

    if (isMongoActive()) {
      const asset = await Asset.findOne({ _id: id, organizationId: org._id });
      if (!asset) {
        return NextResponse.json(
          { success: false, error: { code: 'NOT_FOUND', message: 'Asset not found.' } },
          { status: 404 }
        );
      }

      const fqdn = asset.fqdn;
      const rootDomain = asset.rootDomain;

      if (asset.type === 'ROOT_DOMAIN') {
        await Asset.deleteMany({ organizationId: org._id, rootDomain });
        await Finding.deleteMany({ organizationId: org._id, rootDomain });
      } else {
        await Asset.deleteOne({ _id: asset._id });
        await Finding.deleteMany({ organizationId: org._id, assetId: asset._id });
      }

      try {
        const orgScore = await computeOrgRiskScore(org._id.toString());
        await recordRiskScoreSnapshot(org._id.toString(), orgScore, 'FINDING_MUTATED');
      } catch (scoreErr) {
        console.warn('[AssetDelete] Risk score recompute notice:', scoreErr);
      }

      await AuditLog.create({
        organizationId: org._id,
        actorId: user._id.toString(),
        action: 'ASSET_DELETED',
        objectType: 'Asset',
        objectId: id,
        result: 'SUCCESS',
        details: { fqdn, rootDomain, type: asset.type },
      });

      return NextResponse.json({
        success: true,
        message: `Asset ${fqdn} successfully deleted from inventory.`,
      });
    }

    // In-memory fallback
    const allAssets = Array.from(memoryStore.assets.entries());
    const match = allAssets.find(
      ([k, a]) =>
        (a._id?.toString() === id || a.id === id || k === id) &&
        a.organizationId?.toString() === org._id.toString()
    );

    if (!match) {
      return NextResponse.json(
        { success: false, error: { code: 'NOT_FOUND', message: 'Asset not found.' } },
        { status: 404 }
      );
    }

    const [assetKey, asset] = match;
    const fqdn = asset.fqdn;
    const rootDomain = asset.rootDomain;

    if (asset.type === 'ROOT_DOMAIN') {
      for (const [k, a] of Array.from(memoryStore.assets.entries())) {
        if (a.organizationId?.toString() === org._id.toString() && a.rootDomain === rootDomain) {
          memoryStore.assets.delete(k);
        }
      }
      for (const [k, f] of Array.from(memoryStore.findings.entries())) {
        if (f.organizationId?.toString() === org._id.toString() && f.rootDomain === rootDomain) {
          memoryStore.findings.delete(k);
        }
      }
    } else {
      memoryStore.assets.delete(assetKey);
      for (const [k, f] of Array.from(memoryStore.findings.entries())) {
        if (
          f.organizationId?.toString() === org._id.toString() &&
          (f.assetId?.toString() === id || f.assetFqdn === fqdn)
        ) {
          memoryStore.findings.delete(k);
        }
      }
    }

    try {
      const orgScore = await computeOrgRiskScore(org._id.toString());
      await recordRiskScoreSnapshot(org._id.toString(), orgScore, 'FINDING_MUTATED');
    } catch {}

    memoryStore.auditLogs.push({
      organizationId: org._id,
      actorId: user._id.toString(),
      action: 'ASSET_DELETED',
      objectType: 'Asset',
      objectId: id,
      result: 'SUCCESS',
      details: { fqdn, rootDomain, type: asset.type },
      createdAt: new Date(),
    });

    return NextResponse.json({
      success: true,
      message: `Asset ${fqdn} successfully deleted from inventory.`,
    });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'ASSET_DELETE_ERROR', message: error.message } },
      { status: 500 }
    );
  }
}

