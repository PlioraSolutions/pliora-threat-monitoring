import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { Asset } from '@/models/Asset';
import { AuditLog } from '@/models/AuditLog';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { runPassiveDiscovery } from '@/lib/discovery/engine';

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ id: string }> | { id: string } }
) {
  try {
    const { user, organization: org } = await requireAuth(request);
    const resolvedParams = await Promise.resolve(context.params);
    const assetId = resolvedParams.id;

    let asset: any;
    if (isMongoActive()) {
      asset = await Asset.findOne({ _id: assetId, organizationId: org._id });
    } else {
      asset = memoryStore.assets.get(assetId);
      if (asset && asset.organizationId.toString() !== org._id.toString()) {
        asset = null;
      }
    }

    if (!asset) {
      return NextResponse.json(
        { success: false, error: { code: 'NOT_FOUND', message: 'Asset not found.' } },
        { status: 404 }
      );
    }

    const isParentVerified =
      asset.verificationStatus === 'VERIFIED' ||
      asset.verificationStatus === 'INHERITED_VERIFIED';

    const rootDomain = asset.rootDomain || asset.fqdn;

    const result = await runPassiveDiscovery({
      organizationId: org._id.toString(),
      rootDomain,
      parentVerified: isParentVerified,
    });

    // Record audit log
    if (isMongoActive()) {
      await AuditLog.create({
        organizationId: org._id,
        actorId: user._id.toString(),
        action: 'ASSET_DISCOVERY_RUN',
        objectType: 'Asset',
        objectId: asset._id.toString(),
        result: 'SUCCESS',
        details: {
          rootDomain,
          totalDiscovered: result.totalDiscovered,
          newAssets: result.newAssets,
          mergedAssets: result.mergedAssets,
        },
      });
    } else {
      memoryStore.auditLogs.push({
        organizationId: org._id,
        actorId: user._id.toString(),
        action: 'ASSET_DISCOVERY_RUN',
        objectType: 'Asset',
        objectId: assetId,
        result: 'SUCCESS',
        details: {
          rootDomain,
          totalDiscovered: result.totalDiscovered,
          newAssets: result.newAssets,
          mergedAssets: result.mergedAssets,
        },
        createdAt: new Date(),
      });
    }

    return NextResponse.json({
      success: true,
      data: {
        rootDomain: result.rootDomain,
        totalDiscovered: result.totalDiscovered,
        newAssets: result.newAssets,
        mergedAssets: result.mergedAssets,
        unchangedAssets: result.unchangedAssets,
        sources: result.sources,
        errors: result.errors,
        durationMs: result.durationMs,
        assets: result.assets,
      },
    });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'DISCOVERY_ERROR', message: error.message } },
      { status: 500 }
    );
  }
}
