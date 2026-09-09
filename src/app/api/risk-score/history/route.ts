import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { RiskScoreSnapshot } from '@/models/RiskScoreSnapshot';

export async function GET(request: NextRequest) {
  try {
    const { organization: org } = await requireAuth(request);
    const { searchParams } = new URL(request.url);
    const limit = Math.min(100, Math.max(1, parseInt(searchParams.get('limit') || '30', 10)));

    let snapshots: any[] = [];

    if (isMongoActive()) {
      snapshots = await RiskScoreSnapshot.find({ organizationId: org._id })
        .sort({ computedAt: -1 })
        .limit(limit)
        .lean();
    } else {
      snapshots = memoryStore.riskScoreSnapshots
        .filter((s) => s.organizationId.toString() === org._id.toString())
        .sort((a, b) => new Date(b.computedAt).getTime() - new Date(a.computedAt).getTime())
        .slice(0, limit);
    }

    return NextResponse.json({
      success: true,
      data: snapshots,
    });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'RISK_HISTORY_ERROR', message: error.message } },
      { status: 500 }
    );
  }
}
