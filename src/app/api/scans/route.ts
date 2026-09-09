import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { requireAuth } from '@/lib/auth';
import { Asset } from '@/models/Asset';
import { Scan } from '@/models/Scan';
import { AuditLog } from '@/models/AuditLog';
import { enqueueScanJob, registerScanProcessor } from '@/lib/queue';
import { processScanJob } from '@/workers/scanProcessor';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';

// Register scan worker
registerScanProcessor(processScanJob);

const createScanSchema = z.object({
  assetId: z.string().min(1, 'assetId is required'),
  scanType: z
    .enum(['DOMAIN_VERIFICATION', 'DISCOVERY', 'EXPOSURE', 'FULL_SWEEP'])
    .default('FULL_SWEEP'),
});

export async function GET(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request);
    const { searchParams } = new URL(request.url);
    const assetId = searchParams.get('assetId');

    if (isMongoActive()) {
      const query: Record<string, any> = { organizationId: org._id };
      if (assetId) query.targetAssetId = assetId;

      const scans = await Scan.find(query).sort({ createdAt: -1 }).limit(20);
      return NextResponse.json({ success: true, data: scans });
    }

    // In-memory scans
    let scans = Array.from(memoryStore.scans.values()).filter(
      (s) => s.organizationId.toString() === org._id.toString()
    );
    if (assetId) {
      scans = scans.filter((s) => s.targetAssetId.toString() === assetId);
    }
    scans.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    return NextResponse.json({ success: true, data: scans });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'SCAN_LIST_ERROR', message: error.message } },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request);
    const body = await request.json();

    const parseResult = createScanSchema.safeParse(body);
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

    const { assetId, scanType } = parseResult.data;

    let asset: any;
    if (isMongoActive()) {
      asset = await Asset.findOne({ _id: assetId, organizationId: org._id });
    } else {
      asset = memoryStore.assets.get(assetId);
    }

    if (!asset) {
      return NextResponse.json(
        { success: false, error: { code: 'NOT_FOUND', message: 'Asset not found.' } },
        { status: 404 }
      );
    }

    // STRICT SECURITY GATE: Only scan customer-authorized & verified assets
    if (asset.verificationStatus !== 'VERIFIED') {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'UNAUTHORIZED_TARGET',
            message: `Scans are strictly prohibited on unverified assets. You must verify ownership of ${asset.fqdn} via DNS TXT record before scanning.`,
          },
        },
        { status: 403 }
      );
    }

    // Check Organization Concurrent Scans Quota (§2.3 & DoD)
    const maxConcurrent = org.scanQuotas?.concurrentScans || 2;
    let activeScansCount = 0;

    if (isMongoActive()) {
      activeScansCount = await Scan.countDocuments({
        organizationId: org._id,
        status: { $in: ['ACTIVE', 'QUEUED'] },
      });
    } else {
      activeScansCount = Array.from(memoryStore.scans.values()).filter(
        (s) =>
          s.organizationId.toString() === org._id.toString() &&
          (s.status === 'ACTIVE' || s.status === 'QUEUED')
      ).length;
    }

    if (activeScansCount >= maxConcurrent) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'CONCURRENCY_LIMIT_REACHED',
            message: `Organization has reached maximum concurrent scan limit (${maxConcurrent}). Please wait for active or queued scans to complete.`,
          },
        },
        { status: 429 }
      );
    }

    // Check Daily Scan Limit Quota (§C.2 Production Hardening)
    const maxDaily = org.scanQuotas?.dailyScanLimit || 10;
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    let dailyScansCount = 0;

    if (isMongoActive()) {
      dailyScansCount = await Scan.countDocuments({
        organizationId: org._id,
        createdAt: { $gte: oneDayAgo },
      });
    } else {
      dailyScansCount = Array.from(memoryStore.scans.values()).filter(
        (s) =>
          s.organizationId.toString() === org._id.toString() &&
          new Date(s.createdAt || s.startedAt || 0) >= oneDayAgo
      ).length;
    }

    if (dailyScansCount >= maxDaily) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'DAILY_SCAN_LIMIT_EXCEEDED',
            message: `Organization has reached its 24-hour daily scan limit (${maxDaily} scans). Upgrade plan for increased quota.`,
          },
        },
        { status: 429 }
      );
    }

    let newScan: any;
    if (isMongoActive()) {
      newScan = await Scan.create({
        organizationId: org._id,
        targetAssetId: asset._id,
        scanType,
        status: 'QUEUED',
        progress: 0,
        counters: { subdomainsFound: 0, findingsCreated: 0, checksCompleted: 0 },
        startedAt: new Date(),
      });

      await AuditLog.create({
        organizationId: org._id,
        actorId: org.ownerId,
        action: 'SCAN_TRIGGERED',
        objectType: 'Scan',
        objectId: newScan._id.toString(),
        result: 'SUCCESS',
        details: { domain: asset.fqdn, scanType },
      });
    } else {
      const scanId = `scan-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
      newScan = {
        _id: scanId,
        organizationId: org._id,
        targetAssetId: asset._id,
        scanType,
        status: 'QUEUED',
        progress: 0,
        counters: { subdomainsFound: 0, findingsCreated: 0, checksCompleted: 0 },
        startedAt: new Date(),
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      memoryStore.scans.set(scanId, newScan);
    }

    // Enqueue in BullMQ or resilient memory queue
    await enqueueScanJob({
      scanId: newScan._id.toString(),
      organizationId: org._id.toString(),
      assetId: asset._id.toString(),
      scanType,
    });

    return NextResponse.json({ success: true, data: newScan }, { status: 202 });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'SCAN_ENQUEUE_ERROR', message: error.message } },
      { status: 500 }
    );
  }
}
