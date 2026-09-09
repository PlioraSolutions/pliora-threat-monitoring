import { NextRequest } from 'next/server';
import { requireApiKeyAuth, formatApiResponse, formatApiErrorResponse } from '@/lib/auth/apiKeyAuth';
import { computeOrgRiskScore } from '@/lib/risk/orgScore';

export async function GET(request: NextRequest) {
  try {
    const { organization: org, rateLimit } = await requireApiKeyAuth(request);
    const orgIdStr = (org._id || org.id).toString();

    const orgScore = await computeOrgRiskScore(orgIdStr);

    return formatApiResponse(
      orgScore,
      undefined,
      {
        'X-RateLimit-Limit': rateLimit.limit.toString(),
        'X-RateLimit-Remaining': rateLimit.remaining.toString(),
        'X-RateLimit-Reset': rateLimit.resetSeconds.toString(),
      }
    );
  } catch (error: any) {
    return formatApiErrorResponse(error);
  }
}
