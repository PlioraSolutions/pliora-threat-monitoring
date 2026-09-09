'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { Check, ArrowRight, Loader2 } from 'lucide-react';
import { SiteHeader } from '@/components/SiteHeader';
import { SiteFooter } from '@/components/SiteFooter';
import { useAuth } from '@/context/AuthContext';
import { PlanTier as PlanTierEnum } from '@/types';

interface PlanTier {
  tier: PlanTierEnum;
  name: string;
  price: string;
  cadence: string;
  target: string;
  popular?: boolean;
  features: string[];
  ctaLabel: string;
  ctaHref: string;
}

const PLANS: PlanTier[] = [
  {
    tier: 'FREE',
    name: 'Free',
    price: '$0',
    cadence: 'forever',
    target: 'Solo founders & single-product teams needing continuous baseline perimeter hygiene.',
    features: [
      '1 monitored root domain',
      'Weekly automated discovery sweeps',
      'Standard TLS & security header checks',
      'Email alerts on newly discovered findings',
      'Grounded finding evidence logs',
      'Community & documentation support',
    ],
    ctaLabel: 'Start free',
    ctaHref: '/dashboard',
  },
  {
    tier: 'STARTER',
    name: 'Starter',
    price: '$99',
    cadence: 'per month',
    target: 'Growing companies with 2–5 customer-facing web applications or production APIs.',
    popular: true,
    features: [
      'Up to 5 monitored root domains',
      'Daily continuous discovery sweeps',
      'Full TLS configuration & cipher suite checks',
      'Security headers, CSP, and CORS validation',
      'Typosquatting & look-alike domain watch',
      'AI Security Analyst plain-language summaries',
      'Slack & custom webhook integrations',
    ],
    ctaLabel: 'Start 14-day trial',
    ctaHref: '/dashboard',
  },
  {
    tier: 'BUSINESS',
    name: 'Business',
    price: '$299',
    cadence: 'per month',
    target: 'Mature SMBs with up to 20 domains requiring comprehensive attack-surface governance.',
    features: [
      'Up to 20 monitored root domains',
      'Hourly rapid discovery sweeps',
      'Real-time brand & typosquat registration alerts',
      'Mathematical 0–100 business risk engine',
      'Cryptographically hashed evidence records',
      'Compliance-ready executive PDF summaries',
      'Priority support & dedicated onboarding',
    ],
    ctaLabel: 'Start 14-day trial',
    ctaHref: '/dashboard',
  },
];

const COMPARISON_ROWS = [
  {
    category: 'Attack Surface Discovery',
    items: [
      { name: 'Monitored Root Domains', free: '1', starter: '5', business: '20' },
      { name: 'Scan Cadence', free: 'Weekly', starter: 'Daily', business: 'Hourly' },
      { name: 'Certificate Transparency (CT) Ingestion', free: 'Included', starter: 'Included', business: 'Included' },
      { name: 'Passive DNS Subdomain Enumeration', free: 'Included', starter: 'Included', business: 'Included' },
      { name: 'Public Port & Service Banner Detection', free: 'Standard', starter: 'Comprehensive', business: 'Comprehensive' },
    ],
  },
  {
    category: 'Exposure Checks & Evidence',
    items: [
      { name: 'TLS & Deprecated Protocol Checks', free: 'Included', starter: 'Included', business: 'Included' },
      { name: 'HTTP Security Headers (CSP, HSTS, XFO)', free: 'Included', starter: 'Included', business: 'Included' },
      { name: 'Known Vulnerability (CVE) Mapping', free: 'Critical only', starter: 'Full NVD Feed', business: 'Full NVD Feed + EPSS' },
      { name: 'Raw Immutable Evidence Archives', free: '7 days', starter: '90 days', business: '1 year' },
    ],
  },
  {
    category: 'Threat & Brand Intelligence',
    items: [
      { name: 'Typosquatting & Look-alike Detection', free: '—', starter: 'Included', business: 'Priority Zone Feeds' },
      { name: 'WHOIS & Newly Delegated Domain Watch', free: '—', starter: 'Included', business: 'Real-time' },
    ],
  },
  {
    category: 'Intelligence & Operations',
    items: [
      { name: '0–100 Normalized Business Risk Score', free: 'Basic', starter: 'Full Engine', business: 'Full Engine + Custom Weights' },
      { name: 'AI Security Analyst Explanations', free: '—', starter: 'Included', business: 'Included' },
      { name: 'Alert Destinations', free: 'Email', starter: 'Email, Slack, Webhook', business: 'Email, Slack, Webhook, PagerDuty' },
      { name: 'Support SLA', free: 'Community', starter: '24-hour response', business: '4-hour priority response' },
    ],
  },
];

export default function PricingPage() {
  const { user } = useAuth();
  const [loadingTier, setLoadingTier] = useState<string | null>(null);
  const [checkoutError, setCheckoutError] = useState<string | null>(null);

  const handleSelectPlan = async (plan: PlanTier) => {
    if (plan.tier === 'FREE') {
      window.location.href = user ? '/dashboard' : '/register';
      return;
    }

    if (!user) {
      window.location.href = `/register?plan=${plan.tier}`;
      return;
    }

    try {
      setLoadingTier(plan.tier);
      setCheckoutError(null);
      const res = await fetch('/api/billing/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plan: plan.tier }),
      });
      const data = await res.json();
      if (data.success && data.data?.url) {
        window.location.href = data.data.url;
      } else {
        setCheckoutError(data.error?.message || 'Failed to initialize checkout session.');
        setLoadingTier(null);
      }
    } catch (err: any) {
      setCheckoutError(err.message || 'Error connecting to billing service.');
      setLoadingTier(null);
    }
  };

  return (
    <div className="min-h-screen bg-bg text-text-primary selection:bg-accent-muted selection:text-text-primary">
      <SiteHeader />

      <main className="max-w-[1200px] mx-auto px-6 py-16 space-y-20">
        {/* Header (§5) */}
        <div className="max-w-[720px] mx-auto text-center space-y-4">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded border border-border bg-bg-raised text-[12px] font-mono text-text-secondary">
            <span className="w-1.5 h-1.5 rounded-full bg-accent"></span>
            Predictable, transparent subscription tiers
          </div>
          <h1 className="text-[36px] sm:text-[48px] font-semibold tracking-tight text-text-primary leading-tight">
            Simple pricing for complete external coverage.
          </h1>
          <p className="text-[16px] text-text-secondary leading-relaxed max-w-[54ch] mx-auto">
            Scale your monitoring as your footprint grows. Zero setup fees, no intrusive software agents, and cancel anytime.
          </p>

          {checkoutError && (
            <div className="p-3.5 rounded-card border border-sev-critical/30 bg-sev-critical-bg text-sev-critical text-[13px] text-left">
              {checkoutError}
            </div>
          )}
        </div>

        {/* Plan Cards (§5: 2-3 tiers, text-first, standard hover states) */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-stretch">
          {PLANS.map((plan) => (
            <div
              key={plan.name}
              className={`relative flex flex-col justify-between p-8 rounded-card border bg-bg-raised transition-colors duration-hover ${
                plan.popular
                  ? 'border-accent shadow-sm'
                  : 'border-border hover:border-text-tertiary'
              }`}
            >
              {plan.popular && (
                <div className="absolute -top-3 left-8 px-2.5 py-0.5 rounded-badge bg-accent text-white text-[11px] font-mono font-medium tracking-wide">
                  MOST POPULAR
                </div>
              )}

              <div className="space-y-6">
                {/* Plan Title & Price */}
                <div className="space-y-2 border-b border-border pb-6">
                  <h2 className="text-[20px] font-semibold text-text-primary">
                    {plan.name}
                  </h2>
                  <div className="flex items-baseline gap-1.5">
                    <span className="text-[40px] font-mono font-bold text-text-primary leading-none">
                      {plan.price}
                    </span>
                    <span className="text-[13px] text-text-tertiary font-mono">
                      / {plan.cadence}
                    </span>
                  </div>
                  <p className="text-[13px] text-text-secondary leading-relaxed pt-1">
                    {plan.target}
                  </p>
                </div>

                {/* Feature List */}
                <div className="space-y-3">
                  <div className="text-caption font-mono text-text-tertiary uppercase tracking-wider">
                    Included capabilities
                  </div>
                  <ul className="space-y-2.5">
                    {plan.features.map((feat) => (
                      <li key={feat} className="flex items-start gap-3 text-[14px] text-text-secondary">
                        <Check size={16} className="text-sev-low shrink-0 mt-0.5" />
                        <span>{feat}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Card CTA */}
              <div className="pt-8">
                <button
                  type="button"
                  onClick={() => handleSelectPlan(plan)}
                  disabled={loadingTier === plan.tier}
                  className={`w-full py-2.5 px-4 rounded-btn text-body-sm font-medium transition-colors duration-hover flex items-center justify-center gap-2 ${
                    plan.popular
                      ? 'bg-accent text-white hover:bg-accent-hover disabled:opacity-75'
                      : 'border border-border bg-surface text-text-primary hover:bg-surface-raised disabled:opacity-75'
                  }`}
                >
                  {loadingTier === plan.tier ? (
                    <>
                      <Loader2 size={15} className="animate-spin" />
                      <span>Redirecting...</span>
                    </>
                  ) : (
                    <>
                      <span>{plan.ctaLabel}</span>
                      <ArrowRight size={14} />
                    </>
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Feature Comparison Table (§5) */}
        <div className="space-y-8 pt-8 border-t border-border">
          <div className="space-y-2 text-center sm:text-left">
            <div className="text-caption font-mono text-text-tertiary uppercase tracking-wider">
              Detailed breakdown
            </div>
            <h2 className="text-[24px] sm:text-[32px] font-semibold text-text-primary tracking-tight">
              Compare plan features.
            </h2>
          </div>

          <div className="border border-border rounded-card bg-bg-raised overflow-x-auto">
            <table className="w-full text-left text-body-sm border-collapse">
              <thead>
                <tr className="border-b border-border bg-surface">
                  <th className="p-4 font-semibold text-text-primary w-2/5">Feature</th>
                  <th className="p-4 font-mono font-semibold text-text-primary w-1/5 text-center">Free</th>
                  <th className="p-4 font-mono font-semibold text-accent w-1/5 text-center">Starter</th>
                  <th className="p-4 font-mono font-semibold text-text-primary w-1/5 text-center">Business</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {COMPARISON_ROWS.map((group) => (
                  <React.Fragment key={group.category}>
                    <tr className="bg-bg/40 font-mono text-caption text-text-tertiary">
                      <td colSpan={4} className="px-4 py-2 uppercase tracking-wider font-semibold">
                        {group.category}
                      </td>
                    </tr>
                    {group.items.map((row) => (
                      <tr key={row.name} className="hover:bg-surface/40 transition-colors">
                        <td className="p-4 text-text-primary font-medium">{row.name}</td>
                        <td className="p-4 text-center font-mono text-text-secondary">{row.free}</td>
                        <td className="p-4 text-center font-mono text-text-primary font-medium">{row.starter}</td>
                        <td className="p-4 text-center font-mono text-text-primary">{row.business}</td>
                      </tr>
                    ))}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Pricing FAQ Excerpt */}
        <div className="border-t border-border pt-12 space-y-8">
          <div className="space-y-2 text-center sm:text-left">
            <h2 className="text-[22px] font-semibold text-text-primary">
              Frequently asked pricing questions
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-[14px]">
            <div className="p-5 border border-border rounded-card bg-bg-raised space-y-2">
              <div className="font-semibold text-text-primary">
                Can I upgrade or downgrade at any time?
              </div>
              <p className="text-text-secondary leading-relaxed">
                Yes. You can switch plans or cancel your subscription at any point through the console. Changes take effect on the next monthly billing cycle.
              </p>
            </div>

            <div className="p-5 border border-border rounded-card bg-bg-raised space-y-2">
              <div className="font-semibold text-text-primary">
                Do I need a credit card for the Free tier?
              </div>
              <p className="text-text-secondary leading-relaxed">
                No credit card is required. The Free tier is free forever and includes 1 domain with continuous weekly perimeter monitoring.
              </p>
            </div>

            <div className="p-5 border border-border rounded-card bg-bg-raised space-y-2">
              <div className="font-semibold text-text-primary">
                What counts as a &quot;monitored root domain&quot;?
              </div>
              <p className="text-text-secondary leading-relaxed">
                A root domain is any apex domain (e.g. <span className="font-mono text-text-primary">example.com</span>). All discovered subdomains (e.g. <span className="font-mono text-text-primary">api.example.com</span>, <span className="font-mono text-text-primary">staging.example.com</span>) are included without extra cost.
              </p>
            </div>

            <div className="p-5 border border-border rounded-card bg-bg-raised space-y-2">
              <div className="font-semibold text-text-primary">
                Need more than 20 domains?
              </div>
              <p className="text-text-secondary leading-relaxed">
                Organizations with more than 20 root domains can request custom capacity with dedicated API rate limits and custom retention policies.
              </p>
            </div>
          </div>
        </div>

        {/* Bottom CTA */}
        <div className="text-center border-t border-border pt-12 pb-4 space-y-4">
          <h2 className="text-[26px] font-semibold text-text-primary">
            Start protecting your perimeter in minutes.
          </h2>
          <p className="text-[15px] text-text-secondary max-w-[50ch] mx-auto">
            Test your domain for free or launch continuous monitoring with our 14-day trial.
          </p>
          <div className="pt-2 flex justify-center gap-4">
            <Link
              href="/free-assessment"
              className="px-5 py-2.5 rounded-btn bg-accent text-white text-body-sm font-medium hover:bg-accent-hover transition-colors duration-hover inline-flex items-center gap-2"
            >
              <span>Run free assessment</span>
              <ArrowRight size={15} />
            </Link>
            <Link
              href="/dashboard"
              className="px-5 py-2.5 rounded-btn border border-border bg-bg-raised text-text-primary text-body-sm font-medium hover:bg-surface transition-colors duration-hover"
            >
              Go to console
            </Link>
          </div>

          <p className="text-[12px] text-text-tertiary text-center pt-4">
            All subscriptions are subject to our{' '}
            <Link href="/terms" className="text-accent underline hover:text-accent-hover">
              Terms of Service & AUP
            </Link>
            . Read our verified security architecture in our{' '}
            <Link href="/trust" className="text-accent underline hover:text-accent-hover">
              Trust Center
            </Link>
            .
          </p>
        </div>
      </main>

      <SiteFooter />
    </div>
  );
}
