'use client';

import React, { useEffect, useState, useRef } from 'react';

interface Capability {
  number: string;
  title: string;
  description: string;
  detail: string;
}

const CAPABILITIES: Capability[] = [
  {
    number: '01',
    title: 'Discovery',
    description: 'Continuously maps your external footprint (subdomains, exposed services) from passive sources.',
    detail: 'Tails Certificate Transparency logs, interrogates passive DNS aggregators, and maps external edge IPs without touching your production servers.',
  },
  {
    number: '02',
    title: 'Exposure Checks',
    description: 'Flags outdated TLS, missing headers, and known-vulnerable versions, with confidence levels attached.',
    detail: 'Direct handshake checks verify cipher suites, expiration dates, and browser defenses like CSP, HSTS, and CORS with zero guesswork.',
  },
  {
    number: '03',
    title: 'Threat & Brand Monitoring',
    description: 'Watches for typosquat domains and impersonation attempts as they register.',
    detail: 'Algorithmic permutation and homoglyph scanning cross-reference newly delegated domains across global registrar feeds to catch phishing early.',
  },
  {
    number: '04',
    title: 'Risk Engine',
    description: 'Rolls findings into one score a non-technical owner can act on in seconds.',
    detail: 'Weights severity, exposure reach, confidence, and asset criticality so low-impact staging endpoints never drown out critical web exposures.',
  },
  {
    number: '05',
    title: 'AI Security Analyst',
    description: 'Explains each finding in plain language, grounded strictly in the evidence behind it.',
    detail: 'Translates raw protocol signals, headers, and cipher suites into a concise summary, direct business impact, and exact remediation instructions.',
  },
];

export function CapabilitiesSection() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [scrollProgress, setScrollProgress] = useState(0);
  const [reducedMotion, setReducedMotion] = useState(false);

  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReducedMotion(mq.matches);

    const handleScroll = () => {
      if (!containerRef.current || mq.matches) return;
      const rect = containerRef.current.getBoundingClientRect();
      const totalScrollable = rect.height - window.innerHeight;
      if (totalScrollable <= 0) return;

      const current = -rect.top;
      const progress = Math.min(1, Math.max(0, current / totalScrollable));
      setScrollProgress(progress);
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();

    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const activeFloatIndex = scrollProgress * (CAPABILITIES.length - 1);
  const activeIndex = Math.min(CAPABILITIES.length - 1, Math.max(0, Math.round(activeFloatIndex)));

  const scrollToCapability = (idx: number) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const containerTop = window.scrollY + rect.top;
    const totalScrollable = rect.height - window.innerHeight;
    const targetScroll = containerTop + (idx / (CAPABILITIES.length - 1)) * totalScrollable + 5;
    window.scrollTo({ top: targetScroll, behavior: 'smooth' });
  };

  if (reducedMotion) {
    return (
      <section id="capabilities" className="py-20 px-6 border-b border-border bg-bg">
        <div className="max-w-[1200px] mx-auto space-y-12">
          <div className="space-y-2">
            <div className="text-caption font-mono text-text-tertiary uppercase tracking-wider">
              Core Architecture
            </div>
            <h2 className="text-[32px] sm:text-[40px] font-semibold text-text-primary tracking-tight">
              Five continuous monitoring pillars.
            </h2>
            <p className="text-body text-text-secondary max-w-[60ch]">
              A complete, passive external security loop designed for organizations with 1–20 domains.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {CAPABILITIES.map((cap) => (
              <div
                key={cap.number}
                className="p-6 border border-border rounded-card bg-bg-raised space-y-4"
              >
                <div className="text-[48px] font-mono font-medium text-text-primary leading-none">
                  {cap.number}
                </div>
                <h3 className="text-[20px] font-semibold text-text-primary">{cap.title}</h3>
                <p className="text-body text-text-secondary">{cap.description}</p>
                <p className="text-body-sm text-text-tertiary pt-2 border-t border-border">{cap.detail}</p>
              </div>
            ))}
          </div>
        </div>
      </section>
    );
  }

  return (
    <section
      id="capabilities"
      ref={containerRef}
      className="relative min-h-[300vh] border-b border-border bg-bg"
    >
      <div className="sticky top-20 h-[calc(100vh-80px)] flex flex-col justify-center px-6 overflow-hidden">
        <div className="max-w-[1200px] mx-auto w-full space-y-8">
          {/* Section Header */}
          <div className="flex flex-col sm:flex-row sm:items-end justify-between border-b border-border pb-4 gap-2">
            <div>
              <div className="text-caption font-mono text-text-tertiary uppercase tracking-wider">
                Capabilities 01–05
              </div>
              <h2 className="text-[28px] sm:text-[36px] font-semibold text-text-primary tracking-tight">
                Five continuous monitoring pillars.
              </h2>
            </div>
            <div className="text-caption font-mono text-text-tertiary">
              Scroll to scrub · Pillar {activeIndex + 1} of 5
            </div>
          </div>

          {/* Scrubbed Items Container */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center min-h-[480px]">
            {/* Left selector column: Clickable numbers */}
            <div className="lg:col-span-4 flex lg:flex-col justify-between gap-3 border-b lg:border-b-0 lg:border-r border-border pb-4 lg:pb-0 lg:pr-8">
              {CAPABILITIES.map((cap, idx) => {
                const isCurrent = activeIndex === idx;
                return (
                  <button
                    key={cap.number}
                    type="button"
                    onClick={() => scrollToCapability(idx)}
                    className={`text-left flex items-center gap-4 py-3 px-3.5 rounded transition-all duration-hover ${
                      isCurrent
                        ? 'bg-bg-raised text-text-primary font-medium border-l-2 border-accent'
                        : 'text-text-tertiary hover:text-text-secondary border-l-2 border-transparent'
                    }`}
                  >
                    <span className="font-mono text-[20px]">{cap.number}</span>
                    <span className="text-[15px] truncate">{cap.title}</span>
                  </button>
                );
              })}
            </div>

            {/* Right pinned display: The active capability full size/opacity with 280px separation to prevent any overlap */}
            <div className="lg:col-span-8 relative h-[480px] overflow-hidden [mask-image:linear-gradient(to_bottom,transparent_0%,black_15%,black_85%,transparent_100%)]">
              {CAPABILITIES.map((cap, idx) => {
                const distance = Math.abs(idx - activeFloatIndex);
                // Hide if out of viewport range
                if (distance > 1.5) return null;

                // Opacity: Active = 1.0, adjacent (~1.0 distance) = 0.40
                const opacity = Math.max(0.15, 1 - distance * 0.6);
                // Scale: Active = 1.0, adjacent = 0.85
                const scale = Math.max(0.85, 1 - distance * 0.15);
                // Center-to-center offset: 280px separation guarantees items never collide
                const translateY = (idx - activeFloatIndex) * 280;

                return (
                  <div
                    key={cap.number}
                    className="absolute left-0 right-0 top-1/2 flex flex-col justify-center space-y-4 pointer-events-none transition-transform duration-75 ease-out"
                    style={{
                      opacity,
                      transform: `translateY(calc(-50% + ${translateY}px)) scale(${scale})`,
                      transformOrigin: 'left center',
                      zIndex: 10 - Math.round(distance * 5),
                    }}
                  >
                    <div className="flex items-baseline gap-6">
                      <span className="text-[56px] sm:text-[72px] font-mono font-medium text-text-primary leading-none tracking-tight">
                        {cap.number}
                      </span>
                      <h3 className="text-[26px] sm:text-[36px] font-semibold text-text-primary tracking-tight">
                        {cap.title}
                      </h3>
                    </div>

                    <p className="text-[16px] sm:text-[18px] text-text-primary leading-relaxed max-w-[54ch]">
                      {cap.description}
                    </p>

                    {distance < 0.4 && (
                      <p className="text-[13px] sm:text-[14px] font-mono text-text-secondary max-w-[56ch] border-l-2 border-accent pl-3.5 pt-0.5">
                        {cap.detail}
                      </p>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
