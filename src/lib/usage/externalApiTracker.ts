/**
 * PLIŌRA Threat Monitor — External API Usage & Cost-Visibility Tracker
 * 
 * Tracks consumption across free-tier external data sources:
 * 1. GITHUB_CODE_SEARCH (30 req/min, 500 req/day platform ceiling)
 * 2. PASTE_AGGREGATOR (10 req/min, 200 req/day platform ceiling)
 * 3. BREACH_DIRECTORY (10 req/min, 150 req/day platform ceiling)
 * 
 * Enforces platform-wide daily ceilings and per-minute rate limits.
 * Gracefully degrades by skipping checks when limits are approached,
 * ensuring zero cost overruns and continuous scan pipeline operation.
 */

export type ExternalProvider = 'GITHUB_CODE_SEARCH' | 'PASTE_AGGREGATOR' | 'BREACH_DIRECTORY';

export interface ProviderLimits {
  requestsPerMinute: number;
  requestsPerDay: number;
  monthlyBudget: number;
}

export const DEFAULT_PROVIDER_LIMITS: Record<ExternalProvider, ProviderLimits> = {
  GITHUB_CODE_SEARCH: {
    requestsPerMinute: 30,
    requestsPerDay: 500,
    monthlyBudget: 15000,
  },
  PASTE_AGGREGATOR: {
    requestsPerMinute: 10,
    requestsPerDay: 200,
    monthlyBudget: 6000,
  },
  BREACH_DIRECTORY: {
    requestsPerMinute: 10,
    requestsPerDay: 150,
    monthlyBudget: 4500,
  },
};

export interface UsageRecord {
  id: string;
  provider: ExternalProvider;
  organizationId?: string;
  timestamp: number;
  status: 'SUCCESS' | 'RATE_LIMITED' | 'FAILED' | 'SKIPPED';
  statusCode?: number;
  reason?: string;
}

export interface ProviderMetrics {
  provider: ExternalProvider;
  limits: ProviderLimits;
  usedLastMinute: number;
  usedToday: number;
  usedThisMonth: number;
  percentDailyUsed: number;
  totalCalls: number;
  totalSkipped: number;
  orgBreakdown: Record<string, number>;
}

export interface ExternalApiMetricsReport {
  timestamp: string;
  providers: Record<ExternalProvider, ProviderMetrics>;
  totalPlatformCallsToday: number;
  totalPlatformSkippedToday: number;
}

export class ExternalApiUsageTracker {
  private limits: Record<ExternalProvider, ProviderLimits>;
  private callHistory: UsageRecord[] = [];

  constructor(customLimits?: Partial<Record<ExternalProvider, ProviderLimits>>) {
    this.limits = {
      GITHUB_CODE_SEARCH: { ...DEFAULT_PROVIDER_LIMITS.GITHUB_CODE_SEARCH, ...customLimits?.GITHUB_CODE_SEARCH },
      PASTE_AGGREGATOR: { ...DEFAULT_PROVIDER_LIMITS.PASTE_AGGREGATOR, ...customLimits?.PASTE_AGGREGATOR },
      BREACH_DIRECTORY: { ...DEFAULT_PROVIDER_LIMITS.BREACH_DIRECTORY, ...customLimits?.BREACH_DIRECTORY },
    };
  }

  /**
   * Set or override limits for a provider (useful for testing graceful degradation).
   */
  setLimits(provider: ExternalProvider, limits: Partial<ProviderLimits>): void {
    this.limits[provider] = { ...this.limits[provider], ...limits };
  }

  /**
   * Evaluates whether an external API call can safely execute under rate and daily budgets.
   */
  canExecuteCall(provider: ExternalProvider, organizationId?: string): { allowed: boolean; reason?: string } {
    const now = Date.now();
    const oneMinuteAgo = now - 60 * 1000;
    const startOfToday = new Date().setUTCHours(0, 0, 0, 0);

    const providerLimits = this.limits[provider];

    // Filter calls for this provider that were not SKIPPED
    const activeCalls = this.callHistory.filter(
      (c) => c.provider === provider && c.status !== 'SKIPPED'
    );

    // 1. Check rolling 1-minute limit
    const recentCalls = activeCalls.filter((c) => c.timestamp >= oneMinuteAgo).length;
    if (recentCalls >= providerLimits.requestsPerMinute) {
      return {
        allowed: false,
        reason: `Rolling minute rate limit exceeded (${recentCalls}/${providerLimits.requestsPerMinute} req/min).`,
      };
    }

    // 2. Check daily platform budget
    const todayCalls = activeCalls.filter((c) => c.timestamp >= startOfToday).length;
    if (todayCalls >= providerLimits.requestsPerDay) {
      return {
        allowed: false,
        reason: `Daily free-tier platform budget exhausted (${todayCalls}/${providerLimits.requestsPerDay} calls today).`,
      };
    }

    return { allowed: true };
  }

  /**
   * Records execution or skipping of an external API call.
   */
  recordCall(
    provider: ExternalProvider,
    options: {
      organizationId?: string;
      status: 'SUCCESS' | 'RATE_LIMITED' | 'FAILED' | 'SKIPPED';
      statusCode?: number;
      reason?: string;
    }
  ): UsageRecord {
    const record: UsageRecord = {
      id: `${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      provider,
      organizationId: options.organizationId,
      timestamp: Date.now(),
      status: options.status,
      statusCode: options.statusCode,
      reason: options.reason,
    };

    this.callHistory.push(record);

    // Maintain bounded in-memory buffer (keep last 10,000 records)
    if (this.callHistory.length > 10000) {
      this.callHistory = this.callHistory.slice(-5000);
    }

    return record;
  }

  /**
   * Executes an external operation if within quota. If quota is exceeded,
   * gracefully skips execution, logs an informational degradation notice, and returns { executed: false }.
   */
  async executeWithQuota<T>(
    provider: ExternalProvider,
    organizationId: string | undefined,
    fn: () => Promise<T>
  ): Promise<{ executed: true; result: T } | { executed: false; reason: string }> {
    const clearance = this.canExecuteCall(provider, organizationId);

    if (!clearance.allowed) {
      const reason = clearance.reason || 'Quota exceeded';
      console.warn(`[ExternalApiUsageTracker] Provider ${provider} limit reached. Gracefully skipping for org ${organizationId || 'unattributed'}: ${reason}`);
      this.recordCall(provider, {
        organizationId,
        status: 'SKIPPED',
        reason,
      });
      return { executed: false, reason };
    }

    try {
      const result = await fn();
      this.recordCall(provider, {
        organizationId,
        status: 'SUCCESS',
      });
      return { executed: true, result };
    } catch (err: any) {
      const isRateLimit = err?.status === 429 || err?.message?.includes('429') || err?.message?.includes('rate limit');
      this.recordCall(provider, {
        organizationId,
        status: isRateLimit ? 'RATE_LIMITED' : 'FAILED',
        statusCode: err?.status,
        reason: err?.message,
      });
      throw err;
    }
  }

  /**
   * Returns an operational metrics report across all external providers.
   */
  getUsageMetrics(): ExternalApiMetricsReport {
    const now = Date.now();
    const oneMinuteAgo = now - 60 * 1000;
    const startOfToday = new Date().setUTCHours(0, 0, 0, 0);
    const startOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1).getTime();

    const providers: ExternalProvider[] = ['GITHUB_CODE_SEARCH', 'PASTE_AGGREGATOR', 'BREACH_DIRECTORY'];
    const metrics: Record<ExternalProvider, ProviderMetrics> = {} as any;

    let totalPlatformCallsToday = 0;
    let totalPlatformSkippedToday = 0;

    for (const p of providers) {
      const providerCalls = this.callHistory.filter((c) => c.provider === p);
      const activeCalls = providerCalls.filter((c) => c.status !== 'SKIPPED');

      const usedLastMinute = activeCalls.filter((c) => c.timestamp >= oneMinuteAgo).length;
      const usedToday = activeCalls.filter((c) => c.timestamp >= startOfToday).length;
      const usedThisMonth = activeCalls.filter((c) => c.timestamp >= startOfMonth).length;
      const skippedToday = providerCalls.filter((c) => c.status === 'SKIPPED' && c.timestamp >= startOfToday).length;

      totalPlatformCallsToday += usedToday;
      totalPlatformSkippedToday += skippedToday;

      const limits = this.limits[p];
      const percentDailyUsed = limits.requestsPerDay > 0
        ? Math.min(100, Math.round((usedToday / limits.requestsPerDay) * 100))
        : 0;

      const orgBreakdown: Record<string, number> = {};
      for (const call of activeCalls) {
        const orgKey = call.organizationId || 'unattributed';
        orgBreakdown[orgKey] = (orgBreakdown[orgKey] || 0) + 1;
      }

      metrics[p] = {
        provider: p,
        limits,
        usedLastMinute,
        usedToday,
        usedThisMonth,
        percentDailyUsed,
        totalCalls: activeCalls.length,
        totalSkipped: providerCalls.filter((c) => c.status === 'SKIPPED').length,
        orgBreakdown,
      };
    }

    return {
      timestamp: new Date().toISOString(),
      providers: metrics,
      totalPlatformCallsToday,
      totalPlatformSkippedToday,
    };
  }

  /**
   * Resets usage records for clean test isolation.
   */
  resetForTesting(): void {
    this.callHistory = [];
    this.limits = {
      GITHUB_CODE_SEARCH: { ...DEFAULT_PROVIDER_LIMITS.GITHUB_CODE_SEARCH },
      PASTE_AGGREGATOR: { ...DEFAULT_PROVIDER_LIMITS.PASTE_AGGREGATOR },
      BREACH_DIRECTORY: { ...DEFAULT_PROVIDER_LIMITS.BREACH_DIRECTORY },
    };
  }
}

export const externalApiTracker = new ExternalApiUsageTracker();
