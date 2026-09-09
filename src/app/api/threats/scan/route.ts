import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Asset } from '@/models/Asset';
import { runThreatMonitoring } from '@/lib/threats/engine';

export async function POST(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request);

    // Role check: VIEWER cannot trigger scans
    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === org._id?.toString()
    );
    const role = membership?.role || 'VIEWER';

    if (role === 'VIEWER') {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INSUFFICIENT_PERMISSIONS',
            message: 'Viewer role has read-only access and cannot trigger threat monitoring.',
          },
        },
        { status: 403 }
      );
    }

    let body: any = {};
    try {
      body = await request.json();
    } catch {
      // Body is optional
    }

    let targetDomain = body.domain?.toLowerCase()?.trim();
    let verifiedAsset: any = null;

    if (targetDomain) {
      if (isMongoActive()) {
        verifiedAsset = await Asset.findOne({
          organizationId: org._id,
          fqdn: targetDomain,
        });
      } else {
        const orgIdStr = org._id.toString();
        verifiedAsset = Array.from(memoryStore.assets.values()).find(
          (a) =>
            a.organizationId?.toString() === orgIdStr &&
            (a.fqdn === targetDomain || a.rootDomain === targetDomain)
        );
      }

      if (!verifiedAsset) {
        return NextResponse.json(
          {
            success: false,
            error: {
              code: 'ASSET_NOT_FOUND',
              message: `Asset "${targetDomain}" was not found for this organization.`,
            },
          },
          { status: 404 }
        );
      }
    } else {
      // Pick first verified root domain
      if (isMongoActive()) {
        verifiedAsset = await Asset.findOne({
          organizationId: org._id,
          type: 'ROOT_DOMAIN',
          verificationStatus: { $in: ['VERIFIED', 'INHERITED_VERIFIED'] },
        });
      } else {
        const orgIdStr = org._id.toString();
        verifiedAsset = Array.from(memoryStore.assets.values()).find(
          (a) =>
            a.organizationId?.toString() === orgIdStr &&
            a.type === 'ROOT_DOMAIN' &&
            (a.verificationStatus === 'VERIFIED' || a.verificationStatus === 'INHERITED_VERIFIED')
        );
      }

      if (!verifiedAsset) {
        return NextResponse.json(
          {
            success: false,
            error: {
              code: 'NO_VERIFIED_ASSET',
              message: 'No verified root domain found for this organization. Please add and verify a root domain first.',
            },
          },
          { status: 400 }
        );
      }
      targetDomain = verifiedAsset.rootDomain || verifiedAsset.fqdn;
    }

    // Security check: Only verified root domains can trigger brand threat monitoring
    if (
      verifiedAsset.verificationStatus !== 'VERIFIED' &&
      verifiedAsset.verificationStatus !== 'INHERITED_VERIFIED'
    ) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'UNVERIFIED_TARGET',
            message: `Threat monitoring is strictly prohibited on unverified domain "${targetDomain}". Domain ownership must be verified first.`,
          },
        },
        { status: 403 }
      );
    }

    const result = await runThreatMonitoring({
      organizationId: org._id.toString(),
      rootDomain: targetDomain,
      brandKeyword: body.brandKeyword,
      maxDnsChecks: 25,
    });

    return NextResponse.json({
      success: true,
      data: result,
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'THREAT_SCAN_ERROR', message: error.message } },
      { status }
    );
  }
}
