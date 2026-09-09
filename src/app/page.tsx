'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Check, ArrowRight } from 'lucide-react';

import { SiteHeader } from '@/components/SiteHeader';
import { SiteFooter } from '@/components/SiteFooter';
import { TrustMarquee } from '@/components/TrustMarquee';
import { CapabilitiesSection } from '@/components/CapabilitiesSection';
import { SeverityBadge } from '@/components/SeverityBadge';
import { EvidenceBlock } from '@/components/EvidenceBlock';
import { AiAnalystNote } from '@/components/AiAnalystNote';

const CHECKLIST_STEPS = [
  'Querying certificate transparency logs',
  'Checking TLS configuration',
  'Reading security headers',
  'Cross-referencing known exposures',
];

export default function HomePage() {
  const router = useRouter();
  const [domainInput, setDomainInput] = useState('');
  const [isChecking, setIsChecking] = useState(false);
  const [activeStepIndex, setActiveStepIndex] = useState(-1);
  const [checkFinished, setCheckFinished] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);

  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReducedMotion(mq.matches);
  }, []);

  const handleHeroSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cleanDomain = domainInput.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!cleanDomain) return;

    setIsChecking(true);
    setCheckFinished(false);

    if (reducedMotion) {
      setActiveStepIndex(CHECKLIST_STEPS.length);
      setCheckFinished(true);
      return;
    }

    setActiveStepIndex(0);
    setTimeout(() => setActiveStepIndex(1), 200);
    setTimeout(() => setActiveStepIndex(2), 400);
    setTimeout(() => setActiveStepIndex(3), 600);
    setTimeout(() => {
      setActiveStepIndex(CHECKLIST_STEPS.length);
      setCheckFinished(true);
    }, 850);
  };

  const handleResetCheck = () => {
    setIsChecking(false);
    setActiveStepIndex(-1);
    setCheckFinished(false);
  };

  return (
    <div className="min-h-screen bg-bg text-text-primary selection:bg-accent-muted selection:text-text-primary">
      <SiteHeader />

      {/* Hero Section with Cyber-Eye Decorative Background */}
      <section className="relative pt-16 sm:pt-24 pb-20 sm:pb-28 px-6 border-b border-border overflow-hidden bg-bg min-h-[580px] lg:min-h-[660px] flex items-center">
        {/* Static dot-grid texture at <= 0.03 opacity */}
        <div
          className="absolute inset-0 pointer-events-none select-none z-0"
          style={{
            backgroundImage: 'radial-gradient(var(--text-primary) 1px, transparent 1px)',
            backgroundSize: '24px 24px',
            opacity: 0.03,
          }}
          aria-hidden="true"
        />

        {/* Decorative Cyber-Eye Image Background */}
        <div
          className="absolute inset-0 pointer-events-none select-none overflow-hidden z-0 flex items-center justify-end"
          aria-hidden="true"
        >
          {/* Desktop & Large Screen version (16:9 landscape) */}
          <img
            src="/hero-eye.png"
            alt=""
            className="hero-eye-img hidden md:block w-[85%] lg:w-[74%] xl:w-[66%] max-w-none h-full object-contain object-right lg:translate-x-0 opacity-85 lg:opacity-100 transition-opacity duration-300 [mask-image:linear-gradient(to_right,transparent_0%,black_16%,black_100%)] [-webkit-mask-image:linear-gradient(to_right,transparent_0%,black_16%,black_100%)]"
          />

          {/* Mobile & Small Screen version (9:20 portrait) */}
          <img
            src="/hero-eye-mobile.png"
            alt=""
            className="hero-eye-img block md:hidden absolute inset-0 w-full h-full object-cover object-bottom translate-y-[45px] sm:translate-y-[25px] opacity-75 sm:opacity-85 transition-opacity duration-300"
          />
        </div>

        <div className="relative z-10 max-w-[1240px] w-full mx-auto">
          <div className="max-w-[620px] lg:max-w-[660px] space-y-8">
            {/* Tagline */}
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded border border-border bg-bg-raised/90 backdrop-blur-md text-[12px] font-mono text-text-secondary">
              <span className="w-1.5 h-1.5 rounded-full bg-accent"></span>
              External attack-surface monitoring for 1–20-domain SMBs
            </div>

            {/* Headline (§3: splits into lines, each slides up 40px + fades in, staggered 80ms) */}
            <h1 className="text-[40px] sm:text-[56px] lg:text-[68px] font-semibold tracking-tight text-text-primary leading-[1.06]">
              <span className="block hero-line-1">Know what attackers see,</span>
              <span className="block hero-line-2 text-text-secondary">before they use it.</span>
            </h1>

            {/* Subhead (§3: One sentence naming the mechanism) */}
            <p className="hero-subhead text-[16px] sm:text-[18px] leading-relaxed text-text-secondary max-w-[50ch]">
              Continuous external monitoring, shadow-asset discovery, and AI-explained findings — purpose-built for teams without a full-time security hire.
            </p>

            {/* Inline Free-Assessment Input (§3) */}
            <div className="hero-form pt-2 max-w-[540px]">
              {!isChecking ? (
                <form onSubmit={handleHeroSubmit} className="space-y-2">
                  <div className="flex flex-col sm:flex-row gap-2">
                    <div className="relative flex-1">
                      <input
                        type="text"
                        value={domainInput}
                        onChange={(e) => setDomainInput(e.target.value)}
                        placeholder="example.com"
                        className="w-full px-4 py-3 bg-bg-raised/90 backdrop-blur-md border border-border rounded-input text-[15px] font-mono text-text-primary placeholder-text-tertiary focus:outline-none focus:border-accent transition-colors shadow-sm"
                        required
                      />
                    </div>
                    <button
                      type="submit"
                      className="px-5 py-3 rounded-btn bg-accent text-white text-[14px] font-medium hover:bg-accent-hover transition-colors duration-hover flex items-center justify-center gap-2 whitespace-nowrap shadow-sm"
                    >
                      <span>Run free assessment</span>
                      <ArrowRight size={16} />
                    </button>
                  </div>
                  <div className="text-[12px] font-mono text-text-tertiary">
                    Zero agents · 100% passive reconnaissance · No credentials required
                  </div>
                </form>
              ) : (
                /* Sequential Mono Checklist (§3) */
                <div className="border border-border rounded-card bg-bg-raised/95 backdrop-blur-md p-5 space-y-4 font-mono text-body-sm shadow-sm">
                  <div className="flex items-center justify-between border-b border-border pb-2 text-caption text-text-tertiary">
                    <span>Target: {domainInput}</span>
                    <span>Status: {checkFinished ? 'Complete' : 'Running...'}</span>
                  </div>

                  <div className="space-y-2.5">
                    {CHECKLIST_STEPS.map((stepText, idx) => {
                      const isDone = activeStepIndex > idx;
                      const isCurrent = activeStepIndex === idx;

                      return (
                        <div
                          key={stepText}
                          className={`flex items-center gap-3 transition-opacity duration-150 ${
                            isDone
                              ? 'text-text-primary opacity-100'
                              : isCurrent
                              ? 'text-accent opacity-90'
                              : 'text-text-tertiary opacity-30'
                          }`}
                        >
                          <span
                            className={`w-4 h-4 rounded-sm flex items-center justify-center text-[10px] ${
                              isDone
                                ? 'bg-sev-low/20 text-sev-low border border-sev-low/40'
                                : isCurrent
                                ? 'border border-accent text-accent animate-pulse'
                                : 'border border-border text-transparent'
                            }`}
                          >
                            {isDone ? '✓' : ''}
                          </span>
                          <span className="text-[13px]">{stepText}</span>
                        </div>
                      );
                    })}
                  </div>

                  {/* Summary sentence and link to full assessment */}
                  {checkFinished && (
                    <div className="pt-3 border-t border-border space-y-3 font-sans">
                      <div className="text-[14px] font-medium text-text-primary flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-sev-high"></span>
                        3 checks complete — 1 item needs attention.
                      </div>
                      <div className="flex flex-wrap items-center gap-3">
                        <Link
                          href={`/free-assessment?domain=${encodeURIComponent(domainInput.trim())}`}
                          className="px-4 py-2 rounded-btn bg-accent text-white text-[13px] font-medium hover:bg-accent-hover transition-colors duration-hover inline-flex items-center gap-1.5"
                        >
                          <span>View full assessment results</span>
                          <ArrowRight size={14} />
                        </Link>
                        <button
                          type="button"
                          onClick={handleResetCheck}
                          className="text-[13px] text-text-secondary hover:text-text-primary transition-colors"
                        >
                          Check another domain
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* Trust Marquee (§3: 40s linear scroll of real data sources) */}
      <TrustMarquee />

      {/* Capabilities 01–05 (§3: Scroll-pinned section with 72px mono numbers, no icons) */}
      <CapabilitiesSection />

      {/* How It Works (§3: Plain 3-step numbered list, clarity over motion) */}
      <section className="py-20 px-6 border-b border-border bg-bg">
        <div className="max-w-[1200px] mx-auto space-y-12">
          <div className="space-y-2">
            <div className="text-caption font-mono text-text-tertiary uppercase tracking-wider">
              Workflow Architecture
            </div>
            <h2 className="text-[32px] sm:text-[40px] font-semibold text-text-primary tracking-tight">
              How it works.
            </h2>
            <p className="text-body text-text-secondary max-w-[60ch]">
              Three plain steps. Zero agent overhead, no production disturbance, and no credential sharing.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {/* Step 1 */}
            <div className="space-y-4 p-6 border border-border rounded-card bg-bg-raised">
              <div className="text-[32px] font-mono font-medium text-text-primary">
                01
              </div>
              <h3 className="text-[18px] font-semibold text-text-primary">
                Add your domain
              </h3>
              <p className="text-body-sm text-text-secondary leading-relaxed">
                Provide your primary root domain. We immediately register your organization and initiate ownership verification through non-disruptive DNS TXT challenges.
              </p>
            </div>

            {/* Step 2 */}
            <div className="space-y-4 p-6 border border-border rounded-card bg-bg-raised">
              <div className="text-[32px] font-mono font-medium text-text-primary">
                02
              </div>
              <h3 className="text-[18px] font-semibold text-text-primary">
                Discovery runs automatically
              </h3>
              <p className="text-body-sm text-text-secondary leading-relaxed">
                Passive recon maps your entire external perimeter: Certificate Transparency records, DNS zones, TLS certificates, and edge security headers without touching servers.
              </p>
            </div>

            {/* Step 3 */}
            <div className="space-y-4 p-6 border border-border rounded-card bg-bg-raised">
              <div className="text-[32px] font-mono font-medium text-text-primary">
                03
              </div>
              <h3 className="text-[18px] font-semibold text-text-primary">
                Findings arrive with plain-language explanations
              </h3>
              <p className="text-body-sm text-text-secondary leading-relaxed">
                Every detected exposure links directly to immutable raw evidence, alongside an AI-grounded summary detailing business risk and exact remediation steps.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Proof Stats (§3: Real, defensible framing) */}
      <section className="py-16 px-6 border-b border-border bg-bg-raised">
        <div className="max-w-[1200px] mx-auto">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-center sm:text-left">
            <div className="space-y-1">
              <div className="text-[36px] sm:text-[44px] font-mono font-semibold text-text-primary leading-tight">
                5
              </div>
              <div className="text-[14px] font-medium text-text-primary">
                Monitoring pillars
              </div>
              <div className="text-[12px] text-text-tertiary">
                Discovery to AI analysis
              </div>
            </div>

            <div className="space-y-1">
              <div className="text-[36px] sm:text-[44px] font-mono font-semibold text-text-primary leading-tight">
                24/7
              </div>
              <div className="text-[14px] font-medium text-text-primary">
                Continuous monitoring
              </div>
              <div className="text-[12px] text-text-tertiary">
                Not once a quarter
              </div>
            </div>

            <div className="space-y-1">
              <div className="text-[36px] sm:text-[44px] font-mono font-semibold text-text-primary leading-tight">
                1–20
              </div>
              <div className="text-[14px] font-medium text-text-primary">
                Domain SMB scope
              </div>
              <div className="text-[12px] text-text-tertiary">
                Tailored for small teams
              </div>
            </div>

            <div className="space-y-1">
              <div className="text-[36px] sm:text-[44px] font-mono font-semibold text-text-primary leading-tight">
                0
              </div>
              <div className="text-[14px] font-medium text-text-primary">
                Agents or probes
              </div>
              <div className="text-[12px] text-text-tertiary">
                100% passive observation
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* "What a finding looks like" (§3: Truthful proof instead of fake testimonials) */}
      <section className="py-20 px-6 border-b border-border bg-bg">
        <div className="max-w-[1200px] mx-auto space-y-10">
          <div className="space-y-2">
            <div className="text-caption font-mono text-text-tertiary uppercase tracking-wider">
              Output Grounding
            </div>
            <h2 className="text-[32px] sm:text-[40px] font-semibold text-text-primary tracking-tight">
              What a finding looks like.
            </h2>
            <p className="text-body text-text-secondary max-w-[60ch]">
              Truthful proof beats placeholder testimonials. Every finding links a plain-language executive line to raw technical evidence and actionable mitigation.
            </p>
          </div>

          {/* Example finding card */}
          <div className="border border-border rounded-card bg-bg-raised p-6 space-y-6 max-w-[900px]">
            {/* Top header row */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border pb-4">
              <div className="space-y-1">
                <div className="flex items-center gap-3">
                  <SeverityBadge severity="HIGH" />
                  <span className="font-mono text-caption text-text-tertiary">
                    FIND-2026-0841
                  </span>
                  <span className="text-caption font-mono text-sev-low">
                    CONFIRMED
                  </span>
                </div>
                <h3 className="text-[18px] font-semibold text-text-primary pt-1">
                  Missing Content-Security-Policy header
                </h3>
              </div>

              <div className="text-right sm:text-right font-mono text-caption text-text-tertiary">
                <div>Asset: <span className="text-text-primary">api.example.com</span></div>
                <div>Risk score: <span className="text-sev-high font-semibold">74 / 100</span></div>
              </div>
            </div>

            {/* AI Analyst Note */}
            <AiAnalystNote
              summary="Your web perimeter has valid encryption, but lacks browser script restrictions (CSP). Adding recommended headers takes under 15 minutes and hardens client endpoints against script injection."
              impact="Leaves web applications vulnerable to cross-site scripting (XSS) and client-side data leakage if third-party scripts are compromised."
              recommendedAction="Configure the Content-Security-Policy HTTP response header in your reverse proxy or CDN edge."
            />

            {/* Evidence Block */}
            <EvidenceBlock
              checkType="HTTP_HEADERS"
              observedAt="2026-09-04T16:20:00.000Z"
              rawSignal={`HTTP/2 200 OK
date: Fri, 04 Sep 2026 16:20:00 GMT
server: nginx
strict-transport-security: max-age=31536000; includeSubDomains
x-content-type-options: nosniff
x-frame-options: DENY
[MISSING HEADER: content-security-policy]`}
            />
          </div>
        </div>
      </section>

      {/* Final CTA (§3: Static, no animation. One line, one button) */}
      <section className="py-20 px-6 border-b border-border bg-bg-raised text-center">
        <div className="max-w-[700px] mx-auto space-y-6">
          <h2 className="text-[32px] sm:text-[44px] font-semibold text-text-primary tracking-tight">
            Know what attackers see, before they use it.
          </h2>
          <p className="text-[16px] text-text-secondary leading-relaxed">
            Run a free assessment on your domain in under 30 seconds. No agents to install, no sales calls, no credentials needed.
          </p>
          <div className="pt-2 flex justify-center">
            <Link
              href="/free-assessment"
              className="px-6 py-3 rounded-btn bg-accent text-white text-[15px] font-medium hover:bg-accent-hover transition-colors duration-hover inline-flex items-center gap-2"
            >
              <span>Run your free assessment</span>
              <ArrowRight size={16} />
            </Link>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
