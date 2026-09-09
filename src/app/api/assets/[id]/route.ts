import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Asset } from '@/models/Asset';
import { Finding } from '@/models/Finding';
import { AuditLog } from '@/models/AuditLog';
import { computeRiskScore } from '@/lib/risk/computeRiskScore';
import { computeOrgRiskScore, recordRiskScoreSnapshot } from '@/lib/risk/orgScore';
import { AssetImportance } from '@/types';

interface RouteContext {
  params: Promise<{ id: string }>;
}

export async function PATCH(request: NextRequest, context: RouteContext) {
  try {
    const { user, organization: org } = await requireAuth(request);
    const { id } = await context.params;

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
            message: 'Viewer role cannot modify asset configuration.',
          },
        },
        { status: 403 }
      );
    }

    const body = await request.json();
    const { importance, tags } = body;

    if (importance && !['CRITICAL', 'HIGH', 'NORMAL', 'LOW'].includes(importance)) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INVALID_IMPORTANCE',
            message: 'Importance must be one of CRITICAL, HIGH, NORMAL, LOW.',
          },
        },
        { status: 400 }
      );
    }

    let asset: any = null;

    if (isMongoActive()) {
      asset = await Asset.findOne({ _id: id, organizationId: org._id });
      if (!asset) {
        return NextResponse.json(
          { success: false, error: { code: 'NOT_FOUND', message: 'Asset not found.' } },
          { status: 404 }
        );
      }

      const prevImportance = asset.importance;
      if (importance) asset.importance = importance as AssetImportance;
      if (Array.isArray(tags)) asset.tags = tags;
      asset.updatedAt = new Date();
      await asset.save();

      // If importance changed, recompute risk score for all findings on this asset
      if (importance && importance !== prevImportance) {
        const findings = await Finding.find({ assetId: asset._id, organizationId: org._id });
        for (const f of findings) {
          const recomputed = computeRiskScore(
            { severity: f.severity, confidence: f.confidence, category: f.category, findingCode: f.findingCode },
            asset
          );
          f.riskScore = recomputed.score;
          await f.save();
        }

        const orgScore = await computeOrgRiskScore(org._id.toString());
        await recordRiskScoreSnapshot(org._id.toString(), orgScore, 'FINDING_MUTATED');
      }

      await AuditLog.create({
        organizationId: org._id,
        actorId: user._id.toString(),
        action: 'ASSET_UPDATED',
        objectType: 'Asset',
        objectId: asset._id.toString(),
        result: 'SUCCESS',
        details: { importance, tags },
      });
    } else {
      const allAssets = Array.from(memoryStore.assets.values());
      asset = allAssets.find(
        (a) =>
          (a._id?.toString() === id || a.id === id) &&
          a.organizationId?.toString() === org._id.toString()
      );

      if (!asset) {
        return NextResponse.json(
          { success: false, error: { code: 'NOT_FOUND', message: 'Asset not found.' } },
          { status: 404 }
        );
      }

      const prevImportance = asset.importance;
      if (importance) asset.importance = importance as AssetImportance;
      if (Array.isArray(tags)) asset.tags = tags;
      asset.updatedAt = new Date();

      if (importance && importance !== prevImportance) {
        for (const f of Array.from(memoryStore.findings.values())) {
          if (
            f.organizationId?.toString() === org._id.toString() &&
            f.assetId?.toString() === asset._id?.toString()
          ) {
            const recomputed = computeRiskScore(
              { severity: f.severity, confidence: f.confidence, category: f.category, findingCode: f.findingCode },
              asset
            );
            f.riskScore = recomputed.score;
          }
        }

        const orgScore = await computeOrgRiskScore(org._id.toString());
        await recordRiskScoreSnapshot(org._id.toString(), orgScore, 'FINDING_MUTATED');
      }

      memoryStore.auditLogs.push({
        organizationId: org._id,
        actorId: user._id.toString(),
        action: 'ASSET_UPDATED',
        objectType: 'Asset',
        objectId: asset._id?.toString() || id,
        result: 'SUCCESS',
        details: { importance, tags },
        createdAt: new Date(),
      });
    }

    return NextResponse.json({ success: true, data: asset });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'ASSET_UPDATE_ERROR', message: error.message } },
      { status: 500 }
    );
  }
}
