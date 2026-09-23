import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { simulateRiskScoreIfResolved } from '@/lib/risk/orgScore';

export async function POST(request: NextRequest) {
  try {
    const auth = await requireAuth(request);
    const orgId = auth.organization?._id || auth.user?.activeOrganizationId;

    if (!orgId) {
      return NextResponse.json(
        { success: false, error: { code: 'NO_ACTIVE_ORG', message: 'No active organization selected' } },
        { status: 400 }
      );
    }

    const body = await request.json().catch(() => ({}));
    const findingIds: string[] = Array.isArray(body.findingIds) ? body.findingIds : [];

    const simulation = await simulateRiskScoreIfResolved(orgId.toString(), findingIds);

    return NextResponse.json({
      success: true,
      data: simulation,
    });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'SIMULATION_ERROR', message: error.message } },
      { status: error.status || 500 }
    );
  }
}
