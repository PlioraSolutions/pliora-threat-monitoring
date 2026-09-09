'use client';
import React, { useState, useEffect } from 'react';
import { Shield, Check, AlertTriangle, ArrowRight, ExternalLink, RefreshCw, CreditCard } from 'lucide-react';
import { api } from '@/lib/client/api';

interface SubscriptionData {
  plan: string;
  planName: string;
  priceMonthly: number;
  subscriptionStatus: string;
  scanQuotas: {
    maxMonitoredDomains: number;
    dailyScanLimit: number;
    concurrentScans: number;
  };
  domainUsage: {
    currentCount: number;
    maxMonitored: number;
    isOverLimit: boolean;
    warningMessage?: string;
  };
  gracePeriod: {
    isActive: boolean;
    endsAt?: string | null;
  };
  cancelAtPeriodEnd: boolean;
  currentPeriodEnd?: string | null;
  hasPaymentMethod: boolean;
  canAccessWhiteLabel: boolean;
  apiRateLimitPerMin: number;
}

export function BillingOverview({ canEdit = false }: { canEdit?: boolean }) {
  const [data, setData] = useState<SubscriptionData | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchSubscription = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.get('/api/billing/subscription');
      setData(res);
    } catch (err: any) {
      setError(err.message || 'Failed to load subscription details');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSubscription();
  }, []);

  const handleUpgrade = async (targetPlan: 'STARTER' | 'BUSINESS' | 'PRO') => {
    if (!canEdit) return;
    try {
      setActionLoading(targetPlan);
      setError(null);
      const res = await api.post('/api/billing/checkout', { plan: targetPlan });
      if (res?.url) {
        window.location.href = res.url;
      }
    } catch (err: any) {
      setError(err.message || 'Failed to start checkout');
      setActionLoading(null);
    }
  };

  const handleOpenPortal = async () => {
    if (!canEdit) return;
    try {
      setActionLoading('portal');
      setError(null);
      const res = await api.post('/api/billing/portal', {});
      if (res?.url) {
        window.location.href = res.url;
      }
    } catch (err: any) {
      setError(err.message || 'Failed to open billing portal');
      setActionLoading(null);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-12 text-text-tertiary">
        <RefreshCw className="animate-spin mr-2" size={18} />
        <span>Loading subscription details...</span>
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className="space-y-6">
      {/* Grace Period Alert Banner (§3) */}
      {data.gracePeriod?.isActive && (
        <div className="p-4 rounded-card border border-sev-critical/40 bg-sev-critical-bg text-text-primary flex items-start gap-3">
          <AlertTriangle className="text-sev-critical shrink-0 mt-0.5" size={20} />
          <div className="space-y-1">
            <h4 className="text-[14px] font-semibold text-sev-critical">
              Payment Past Due — 7-Day Grace Period Active
            </h4>
            <p className="text-[13px] text-text-secondary leading-relaxed">
              Your recent subscription renewal failed. Monitoring remains active until{' '}
              <strong className="text-text-primary">
                {data.gracePeriod.endsAt ? new Date(data.gracePeriod.endsAt).toLocaleDateString() : 'soon'}
              </strong>
              . Please update your payment method to prevent monitoring interruption.
            </p>
            {canEdit && (
              <button
                onClick={handleOpenPortal}
                className="mt-2 inline-flex items-center gap-1.5 text-[12px] font-medium text-accent hover:underline"
              >
                <CreditCard size={14} />
                <span>Update billing method</span>
              </button>
            )}
          </div>
        </div>
      )}

      {/* Non-Destructive Over-Limit Warning (§4) */}
      {data.domainUsage?.isOverLimit && (
        <div className="p-4 rounded-card border border-sev-medium/40 bg-sev-medium-bg text-text-primary flex items-start gap-3">
          <AlertTriangle className="text-sev-medium shrink-0 mt-0.5" size={20} />
          <div className="space-y-1">
            <h4 className="text-[14px] font-semibold text-sev-medium">
              Domain Quota Limit Reached
            </h4>
            <p className="text-[13px] text-text-secondary leading-relaxed">
              {data.domainUsage.warningMessage}
            </p>
          </div>
        </div>
      )}

      {error && (
        <div className="p-3.5 rounded-card border border-sev-critical/30 bg-sev-critical-bg text-sev-critical text-[13px]">
          {error}
        </div>
      )}

      {/* Current Plan Overview Card */}
      <div className="p-6 rounded-card border border-border bg-bg-raised flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div className="space-y-2">
          <div className="flex items-center gap-2.5">
            <span className="text-caption font-mono text-text-tertiary uppercase tracking-wider">
              Current subscription
            </span>
            <span className="px-2 py-0.5 rounded-badge bg-accent-muted text-accent font-mono text-[11px] font-semibold uppercase">
              {data.plan}
            </span>
            {data.subscriptionStatus !== 'ACTIVE' && (
              <span className="px-2 py-0.5 rounded-badge bg-sev-critical-bg text-sev-critical font-mono text-[11px]">
                {data.subscriptionStatus}
              </span>
            )}
          </div>
          <h3 className="text-[24px] font-bold text-text-primary">
            {data.planName} Plan
          </h3>
          <p className="text-[13px] text-text-secondary">
            {data.priceMonthly > 0 ? `$${data.priceMonthly}/month` : 'Free forever'}
            {data.currentPeriodEnd && ` • Renews ${new Date(data.currentPeriodEnd).toLocaleDateString()}`}
          </p>
        </div>

        {canEdit && (
          <div className="flex items-center gap-3">
            {data.hasPaymentMethod && (
              <button
                type="button"
                onClick={handleOpenPortal}
                disabled={actionLoading === 'portal'}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-btn border border-border bg-surface text-text-primary text-[13px] font-medium hover:bg-surface-raised transition-colors"
              >
                {actionLoading === 'portal' ? (
                  <RefreshCw className="animate-spin" size={14} />
                ) : (
                  <ExternalLink size={14} />
                )}
                <span>Manage billing & invoices</span>
              </button>
            )}

            {data.plan === 'FREE' && (
              <button
                type="button"
                onClick={() => handleUpgrade('STARTER')}
                disabled={actionLoading === 'STARTER'}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-btn bg-accent text-white text-[13px] font-medium hover:bg-accent-hover transition-colors shadow-xs"
              >
                {actionLoading === 'STARTER' ? (
                  <RefreshCw className="animate-spin" size={14} />
                ) : (
                  <ArrowRight size={14} />
                )}
                <span>Upgrade to Starter ($99/mo)</span>
              </button>
            )}

            {data.plan === 'STARTER' && (
              <button
                type="button"
                onClick={() => handleUpgrade('BUSINESS')}
                disabled={actionLoading === 'BUSINESS'}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-btn bg-accent text-white text-[13px] font-medium hover:bg-accent-hover transition-colors shadow-xs"
              >
                {actionLoading === 'BUSINESS' ? (
                  <RefreshCw className="animate-spin" size={14} />
                ) : (
                  <ArrowRight size={14} />
                )}
                <span>Upgrade to Business ($299/mo)</span>
              </button>
            )}
          </div>
        )}
      </div>

      {/* Quotas & Tier Features Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Monitored Domains Quota */}
        <div className="p-5 rounded-card border border-border bg-bg-raised space-y-2">
          <div className="text-caption font-mono text-text-tertiary">MONITORED DOMAINS</div>
          <div className="text-[26px] font-mono font-semibold text-text-primary">
            {data.domainUsage.currentCount}{' '}
            <span className="text-[15px] font-normal text-text-tertiary">
              / {data.scanQuotas.maxMonitoredDomains}
            </span>
          </div>
          <div className="w-full bg-surface rounded-full h-1.5 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all ${
                data.domainUsage.isOverLimit ? 'bg-sev-critical' : 'bg-accent'
              }`}
              style={{
                width: `${Math.min(
                  100,
                  (data.domainUsage.currentCount / data.scanQuotas.maxMonitoredDomains) * 100
                )}%`,
              }}
            />
          </div>
        </div>

        {/* Daily Scan Limit */}
        <div className="p-5 rounded-card border border-border bg-bg-raised space-y-2">
          <div className="text-caption font-mono text-text-tertiary">DAILY SCAN QUOTA</div>
          <div className="text-[26px] font-mono font-semibold text-text-primary">
            {data.scanQuotas.dailyScanLimit}
          </div>
          <p className="text-[12px] text-text-secondary">Scans per 24-hour rolling window</p>
        </div>

        {/* Concurrency Limit */}
        <div className="p-5 rounded-card border border-border bg-bg-raised space-y-2">
          <div className="text-caption font-mono text-text-tertiary">CONCURRENT SCANS</div>
          <div className="text-[26px] font-mono font-semibold text-text-primary">
            {data.scanQuotas.concurrentScans}
          </div>
          <p className="text-[12px] text-text-secondary">Simultaneous active scan worker jobs</p>
        </div>

        {/* API Rate Limit & White Label */}
        <div className="p-5 rounded-card border border-border bg-bg-raised space-y-2">
          <div className="text-caption font-mono text-text-tertiary">API KEY RATE LIMIT</div>
          <div className="text-[26px] font-mono font-semibold text-text-primary">
            {data.apiRateLimitPerMin}{' '}
            <span className="text-[12px] font-normal text-text-tertiary">req/min</span>
          </div>
          <p className="text-[12px] text-text-secondary">
            White-label PDF:{' '}
            <span className={data.canAccessWhiteLabel ? 'text-sev-low font-medium' : 'text-text-tertiary'}>
              {data.canAccessWhiteLabel ? 'Available' : 'Business Tier Only'}
            </span>
          </p>
        </div>
      </div>
    </div>
  );
}
