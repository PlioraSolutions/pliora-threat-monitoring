'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { ChevronDown, ArrowRight, HelpCircle } from 'lucide-react';
import { SiteHeader } from '@/components/SiteHeader';
import { SiteFooter } from '@/components/SiteFooter';

interface FaqItem {
  id: string;
  category: string;
  question: string;
  answer: string;
}

const FAQ_ITEMS: FaqItem[] = [
  {
    id: 'faq-1',
    category: 'Reconnaissance & Safety',
    question: 'Will scanning disrupt, slow down, or impact our production services?',
    answer:
      'No. PLIŌRA relies exclusively on non-intrusive, passive reconnaissance. We inspect public Certificate Transparency logs, query recursive DNS resolvers, and perform standard single TLS handshakes. We never send exploit payloads, run credential stuffing, or conduct high-volume port floods. Production impact is mathematically negligible—identical to a single regular web browser visit.',
  },
  {
    id: 'faq-2',
    category: 'Reconnaissance & Safety',
    question: 'Do we need to install software agents on our servers or cloud instances?',
    answer:
      'Never. PLIŌRA operates 100% agentless from the outside in. We view your attack surface exactly as an external adversary sees it—using publicly observable internet telemetry. You never need to install software packages, manage agent update daemons, or grant root privileges.',
  },
  {
    id: 'faq-3',
    category: 'Domain Verification',
    question: 'Why is domain ownership verification required for full continuous monitoring?',
    answer:
      'While our public free assessment is non-invasive and open for any domain, continuous background monitoring and private finding histories require proof of domain control. This prevents unauthorized third parties from setting up automated monitoring on assets they do not own, ensuring strict tenant boundaries and privacy compliance.',
  },
  {
    id: 'faq-4',
    category: 'Domain Verification',
    question: 'How do we verify domain ownership?',
    answer:
      'We generate a cryptographically random challenge token for your domain. You can verify in under two minutes by adding a single DNS TXT record (e.g. _pliora-challenge.yourdomain.com) or uploading a text file to /.well-known/pliora-verification.txt. Our worker validates this via DNS-over-HTTPS (DoH) and enables continuous sweeps immediately upon confirmation.',
  },
  {
    id: 'faq-5',
    category: 'Evidence & Accuracy',
    question: 'How does PLIŌRA eliminate false positives?',
    answer:
      'Every finding in PLIŌRA is strictly tied to an immutable raw evidence record containing the verbatim protocol signal (such as exact HTTP header strings, TLS cipher list, or DNS response packets). Findings are rated with confidence levels (CONFIRMED, HIGH, MEDIUM) so you can distinguish verified misconfigurations from theoretical warnings.',
  },
  {
    id: 'faq-6',
    category: 'Evidence & Accuracy',
    question: 'How does the AI Security Analyst ensure answers are not hallucinations?',
    answer:
      'The AI Analyst is strictly prompt-sandboxed and evidence-grounded. It is restricted to explaining only what is explicitly verified in the raw evidence block. It translates technical headers and cipher suites into a plain-language summary, direct business impact, and concrete remediation steps without inventing non-existent vulnerabilities.',
  },
  {
    id: 'faq-7',
    category: 'Risk Scoring & Threats',
    question: 'How is the 0–100 Risk Score calculated?',
    answer:
      'Our deterministic risk engine calculates impact using a transparent mathematical model: Severity × Exposure × Confidence × Asset Criticality. A high-severity issue on an internal staging endpoint will not artificially dominate your risk score over an exposed production apex, allowing non-technical leaders to fix what matters most.',
  },
  {
    id: 'faq-8',
    category: 'Risk Scoring & Threats',
    question: 'What is typosquatting and brand look-alike domain monitoring?',
    answer:
      'Attackers frequently register domains that resemble your brand (such as examp1e.com or company-portal.com) to target employees or customers with phishing. PLIŌRA generates homoglyph and character permutations and cross-references newly delegated ICANN zone files, alerting you the moment an impersonation domain is registered.',
  },
  {
    id: 'faq-9',
    category: 'Platform & Privacy',
    question: 'How is organizational scan data kept private and secure?',
    answer:
      'All asset inventories, raw evidence records, and finding reports are encrypted at rest with AES-256 and partitioned with strict tenant isolation keys. Only authenticated team members in your organization can access your asset footprint, and scan telemetry is never shared with third parties or search engines.',
  },
];

export default function FaqPage() {
  const [openIds, setOpenIds] = useState<string[]>(['faq-1']);
  const [reducedMotion, setReducedMotion] = useState(false);

  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReducedMotion(mq.matches);
  }, []);

  const toggleItem = (id: string) => {
    setOpenIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  return (
    <div className="min-h-screen bg-bg text-text-primary selection:bg-accent-muted selection:text-text-primary">
      <SiteHeader />

      <main className="max-w-[1200px] mx-auto px-6 py-16 space-y-16">
        {/* Header (§6) */}
        <div className="max-w-[720px] mx-auto text-center space-y-4">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded border border-border bg-bg-raised text-[12px] font-mono text-text-secondary">
            <span className="w-1.5 h-1.5 rounded-full bg-accent"></span>
            Technical specifications & operational answers
          </div>
          <h1 className="text-[36px] sm:text-[48px] font-semibold tracking-tight text-text-primary leading-tight">
            Frequently asked questions.
          </h1>
          <p className="text-[16px] text-text-secondary leading-relaxed max-w-[56ch] mx-auto">
            Everything you need to know about passive perimeter discovery, verified evidence grounding, and continuous external threat monitoring.
          </p>
        </div>

        {/* Accordion List (§6: click to expand answer, 200ms height transition, chevron rotates 180 deg) */}
        <div className="max-w-[840px] mx-auto space-y-3">
          {FAQ_ITEMS.map((item) => {
            const isOpen = openIds.includes(item.id);

            return (
              <div
                key={item.id}
                className="border border-border rounded-card bg-bg-raised overflow-hidden transition-colors"
              >
                <button
                  type="button"
                  onClick={() => toggleItem(item.id)}
                  aria-expanded={isOpen}
                  className="w-full p-5 flex items-center justify-between gap-4 text-left hover:bg-surface/50 transition-colors focus:outline-none"
                >
                  <div className="space-y-1 pr-2">
                    <span className="text-[11px] font-mono uppercase tracking-wider text-text-tertiary block">
                      {item.category}
                    </span>
                    <span className="text-[16px] font-semibold text-text-primary block">
                      {item.question}
                    </span>
                  </div>

                  <div
                    className={`shrink-0 text-text-tertiary transition-transform duration-200 ${
                      isOpen ? 'rotate-180 text-text-primary' : 'rotate-0'
                    }`}
                  >
                    <ChevronDown size={18} />
                  </div>
                </button>

                {isOpen && (
                  <div
                    className={`px-5 pb-5 pt-1 text-[14px] leading-relaxed text-text-secondary border-t border-border/60 ${
                      reducedMotion ? '' : 'transition-all duration-200 ease-out'
                    }`}
                  >
                    <p className="max-w-[70ch]">{item.answer}</p>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Support Callout */}
        <div className="max-w-[840px] mx-auto p-8 border border-border rounded-card bg-surface flex flex-col sm:flex-row items-center justify-between gap-6">
          <div className="space-y-1 text-center sm:text-left">
            <h3 className="text-[18px] font-semibold text-text-primary">
              Have a specific technical question?
            </h3>
            <p className="text-[14px] text-text-secondary">
              Our engineering team is available to review custom protocol inquiries or enterprise telemetry integration needs.
            </p>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <Link
              href="/free-assessment"
              className="px-4 py-2 rounded-btn bg-accent text-white text-body-sm font-medium hover:bg-accent-hover transition-colors duration-hover inline-flex items-center gap-1.5"
            >
              <span>Test your domain</span>
              <ArrowRight size={14} />
            </Link>
          </div>
        </div>
      </main>

      <SiteFooter />
    </div>
  );
}
