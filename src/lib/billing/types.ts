import { PlanTier, SubscriptionStatus } from '@/types';

export interface PlanDefinition {
  id: PlanTier;
  name: string;
  priceMonthly: number;
  currency: string;
  cadence: 'monthly' | 'yearly';
  quotas: {
    maxMonitoredDomains: number;
    dailyScanLimit: number;
    concurrentScans: number;
    apiRateLimitPerMin: number;
    whiteLabelAllowed: boolean;
  };
  features: string[];
}

export interface CheckoutSessionOptions {
  organizationId: string;
  plan: PlanTier;
  successUrl: string;
  cancelUrl: string;
  customerEmail?: string;
}

export interface CustomerPortalOptions {
  organizationId: string;
  returnUrl: string;
}

export interface BillingWebhookPayload {
  id: string;
  type: string;
  data: {
    object: Record<string, any>;
  };
  created: number;
}
