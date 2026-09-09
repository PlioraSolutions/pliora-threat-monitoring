import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { computeOrgRiskScore } from '@/lib/risk/orgScore';

export async function GET(request: NextRequest) {
  try {
    const { organization: org } = await requireAuth(request);
    const orgScore = await computeOrgRiskScore(org._id.toString());

    return NextResponse.json({
      success: true,
      data: orgScore,
    });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'RISK_SCORE_ERROR', message: error.message } },
      { status: 500 }
    );
  }
}
