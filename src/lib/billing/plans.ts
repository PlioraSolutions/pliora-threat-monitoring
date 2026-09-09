import { PlanTier } from '@/types';
import { PlanDefinition } from './types';

export const PLANS: Record<PlanTier, PlanDefinition> = {
  FREE: {
    id: 'FREE',
    name: 'Free',
    priceMonthly: 0,
    currency: 'USD',
    cadence: 'monthly',
    quotas: {
      maxMonitoredDomains: 1,
      dailyScanLimit: 5,
      concurrentScans: 1,
      apiRateLimitPerMin: 20,
      whiteLabelAllowed: false,
    },
    features: [
      '1 monitored root domain',
      'Weekly automated discovery sweeps',
      'Standard TLS & security header checks',
      'Email alerts on newly discovered findings',
      'Grounded finding evidence logs',
      'Community & documentation support',
    ],
  },
  STARTER: {
    id: 'STARTER',
    name: 'Starter',
    priceMonthly: 99,
    currency: 'USD',
    cadence: 'monthly',
    quotas: {
      maxMonitoredDomains: 5,
      dailyScanLimit: 25,
      concurrentScans: 2,
      apiRateLimitPerMin: 120,
      whiteLabelAllowed: false,
    },
    features: [
      'Up to 5 monitored root domains',
      'Daily continuous discovery sweeps',
      'Full TLS configuration & cipher suite checks',
      'Security headers, CSP, and CORS validation',
      'Typosquatting & look-alike domain watch',
      'AI Security Analyst plain-language summaries',
      'Slack & custom webhook integrations',
    ],
  },
  BUSINESS: {
    id: 'BUSINESS',
    name: 'Business',
    priceMonthly: 299,
    currency: 'USD',
    cadence: 'monthly',
    quotas: {
      maxMonitoredDomains: 20,
      dailyScanLimit: 100,
      concurrentScans: 5,
      apiRateLimitPerMin: 300,
      whiteLabelAllowed: true,
    },
    features: [
      'Up to 20 monitored root domains',
      'Hourly rapid discovery sweeps',
      'Real-time brand & typosquat registration alerts',
      'Mathematical 0–100 business risk engine',
      'Cryptographically hashed evidence records',
      'Compliance-ready executive PDF summaries with custom white-label branding',
      'Priority support & dedicated onboarding',
    ],
  },
  PRO: {
    id: 'PRO',
    name: 'Pro',
    priceMonthly: 599,
    currency: 'USD',
    cadence: 'monthly',
    quotas: {
      maxMonitoredDomains: 50,
      dailyScanLimit: 500,
      concurrentScans: 10,
      apiRateLimitPerMin: 600,
      whiteLabelAllowed: true,
    },
    features: [
      'Up to 50 monitored root domains',
      'Continuous real-time asset discovery',
      'Custom vulnerability & port scans',
      'Unlimited exportable PDF reports with white-label branding',
      'Dedicated compliance audit support',
    ],
  },
};

export function getPlanDefinition(plan: PlanTier = 'FREE'): PlanDefinition {
  return PLANS[plan] || PLANS.FREE;
}

export function getPlanQuotas(plan: PlanTier = 'FREE') {
  return (PLANS[plan] || PLANS.FREE).quotas;
}

export function canAccessWhiteLabel(plan: PlanTier = 'FREE'): boolean {
  return (PLANS[plan] || PLANS.FREE).quotas.whiteLabelAllowed;
}

export function getApiRateLimit(plan: PlanTier = 'FREE'): number {
  return (PLANS[plan] || PLANS.FREE).quotas.apiRateLimitPerMin;
}
