import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Asset } from '@/models/Asset';
import { getPlanDefinition, canAccessWhiteLabel, getApiRateLimit } from '@/lib/billing/plans';
import { PlanTier } from '@/types';

export async function GET(request: NextRequest) {
  try {
    const { organization: org } = await requireAuth(request, { allowDevDemoFallback: false });
    const orgId = org._id || org.id;

    // Count currently monitored root domains
    let monitoredDomainsCount = 0;
    if (isMongoActive()) {
      monitoredDomainsCount = await Asset.countDocuments({
        organizationId: orgId,
        type: 'ROOT_DOMAIN',
      });
    } else {
      monitoredDomainsCount = Array.from(memoryStore.assets.values()).filter(
        (a) => a.organizationId?.toString() === orgId.toString() && a.type === 'ROOT_DOMAIN'
      ).length;
    }

    const currentPlan: PlanTier = org.plan || 'FREE';
    const planDef = getPlanDefinition(currentPlan);
    const maxMonitored = org.scanQuotas?.maxMonitoredDomains ?? planDef.quotas.maxMonitoredDomains;
    const isOverLimit = monitoredDomainsCount > maxMonitored;

    const isGracePeriodActive = Boolean(
      org.gracePeriodEnd && new Date(org.gracePeriodEnd).getTime() > Date.now()
    );

    return NextResponse.json({
      success: true,
      data: {
        plan: currentPlan,
        planName: planDef.name,
        priceMonthly: planDef.priceMonthly,
        subscriptionStatus: org.subscriptionStatus || 'ACTIVE',
        scanQuotas: {
          maxMonitoredDomains: maxMonitored,
          dailyScanLimit: org.scanQuotas?.dailyScanLimit ?? planDef.quotas.dailyScanLimit,
          concurrentScans: org.scanQuotas?.concurrentScans ?? planDef.quotas.concurrentScans,
        },
        domainUsage: {
          currentCount: monitoredDomainsCount,
          maxMonitored,
          isOverLimit,
          warningMessage: isOverLimit
            ? `Your organization currently monitors ${monitoredDomainsCount} domains, exceeding your ${planDef.name} limit (${maxMonitored}). Existing assets remain monitored, but adding new domains is restricted until upgraded.`
            : undefined,
        },
        gracePeriod: {
          isActive: isGracePeriodActive,
          endsAt: org.gracePeriodEnd || null,
        },
        cancelAtPeriodEnd: Boolean(org.cancelAtPeriodEnd),
        currentPeriodEnd: org.currentPeriodEnd || null,
        hasPaymentMethod: Boolean(org.stripeCustomerId),
        canAccessWhiteLabel: canAccessWhiteLabel(currentPlan),
        apiRateLimitPerMin: getApiRateLimit(currentPlan),
      },
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      {
        success: false,
        error: {
          code: error.code || 'SUBSCRIPTION_FETCH_FAILED',
          message: error.message || 'Failed to retrieve subscription and quota details.',
        },
      },
      { status }
    );
  }
}
