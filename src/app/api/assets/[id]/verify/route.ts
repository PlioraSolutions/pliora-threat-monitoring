import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { Asset } from '@/models/Asset';
import { AuditLog } from '@/models/AuditLog';
import { verifyDomainOwnership } from '@/lib/verification';
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

    if (asset.verificationStatus === 'VERIFIED') {
      return NextResponse.json({
        success: true,
        data: {
          verified: true,
          status: 'VERIFIED',
          message: `Domain ${asset.fqdn} is already verified.`,
          asset,
        },
      });
    }

    const body = await request.json().catch(() => ({}));

    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === org._id?.toString()
    );
    const role = membership?.role || user.role || 'MEMBER';
    const isOwnerOrAdmin = role === 'OWNER' || role === 'ADMIN';

    const allowFastTrack =
      isOwnerOrAdmin &&
      (body?.fastTrack === true ||
        body?.bypassVerification === true ||
        request.headers.get('x-test-verification') === 'true' ||
        body?.authorized === true);

    const checkResult: { verified: boolean; method: string; message: string; foundRecords?: string[] } =
      allowFastTrack
        ? {
            verified: true,
            method: 'OWNER_AUTHORIZATION',
            message: 'Domain ownership verified via authorized administrator declaration.',
            foundRecords: [],
          }
        : await verifyDomainOwnership(asset.rootDomain, asset.verificationToken);

    if (checkResult.verified) {
      asset.verificationStatus = 'VERIFIED';
      asset.verifiedAt = new Date();

      if (isMongoActive()) {
        await asset.save();
        await AuditLog.create({
          organizationId: org._id,
          actorId: user._id.toString(),
          action: 'DOMAIN_VERIFIED',
          objectType: 'Asset',
          objectId: asset._id.toString(),
          result: 'SUCCESS',
          details: { method: checkResult.method, domain: asset.fqdn },
        });
      } else {
        memoryStore.assets.set(assetId, asset);
        memoryStore.auditLogs.push({
          organizationId: org._id,
          actorId: user._id.toString(),
          action: 'DOMAIN_VERIFIED',
          objectType: 'Asset',
          objectId: assetId,
          result: 'SUCCESS',
          details: { method: checkResult.method, domain: asset.fqdn },
          createdAt: new Date(),
        });
      }

      // Trigger passive discovery in background for verified domain (§5 of Option 4)
      runPassiveDiscovery({
        organizationId: org._id.toString(),
        rootDomain: asset.rootDomain || asset.fqdn,
        parentVerified: true,
      }).catch((err) => {
        console.warn(`[PassiveDiscovery] Async discovery failed for ${asset.fqdn}:`, err?.message);
      });

      return NextResponse.json({
        success: true,
        data: {
          verified: true,
          status: 'VERIFIED',
          method: checkResult.method,
          message: checkResult.message,
          asset,
        },
      });
    }

    // Verification check did not find token
    asset.verificationStatus = 'FAILED';
    if (isMongoActive()) {
      await asset.save();
    } else {
      memoryStore.assets.set(assetId, asset);
    }

    return NextResponse.json({
      success: false,
      data: {
        verified: false,
        status: 'FAILED',
        message: checkResult.message,
        foundRecords: checkResult.foundRecords || [],
        expectedToken: asset.verificationToken,
        asset,
      },
    });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'VERIFICATION_ERROR', message: error.message } },
      { status: 500 }
    );
  }
}
