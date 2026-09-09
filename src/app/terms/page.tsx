'use client';

import React from 'react';
import Link from 'next/link';
import { Shield, CheckCircle2, AlertTriangle, Mail, ArrowLeft } from 'lucide-react';
import { SiteHeader } from '@/components/SiteHeader';
import { SiteFooter } from '@/components/SiteFooter';

export default function TermsPage() {
  return (
    <div className="min-h-screen bg-bg text-text-primary flex flex-col transition-colors">
      <SiteHeader />

      <main className="flex-1 max-w-[900px] w-full mx-auto px-6 py-16">
        <Link
          href="/"
          className="inline-flex items-center gap-2 text-caption text-text-secondary hover:text-text-primary transition-colors mb-8"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Home</span>
        </Link>

        {/* Header */}
        <div className="space-y-4 mb-12 border-b border-border pb-8">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-border bg-surface text-caption text-text-secondary">
            <Shield className="w-3.5 h-3.5 text-accent" />
            <span>Legal & Operational Policy</span>
          </div>
          <h1 className="text-display font-semibold tracking-tight text-text-primary">
            Terms of Service & Acceptable Use Policy
          </h1>
          <p className="text-body text-text-secondary">
            Last Updated: September 6, 2026 · Effective Date: Immediate
          </p>
        </div>

        {/* Content sections */}
        <div className="space-y-10 text-body leading-relaxed text-text-secondary">
          {/* Section 1: Authorized Scope */}
          <section className="space-y-3">
            <h2 className="text-h2 font-semibold text-text-primary flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-sev-low shrink-0" />
              1. Authorized Scanning Scope
            </h2>
            <p>
              PLIŌRA Threat Monitor is designed strictly to observe, analyze, and report on the external attack surface of internet assets owned, operated, or explicitly authorized by your organization.
            </p>
            <p>
              Before any active scan job is scheduled, the target root domain must undergo cryptographic or DNS-based verification (TXT token or HTTP challenge). Subdomains inherit verification strictly under the apex domain registered by the customer. Probing or monitoring unverified third-party infrastructure is strictly prohibited.
            </p>
          </section>

          {/* Section 2: Passive Reconnaissance */}
          <section className="space-y-3">
            <h2 className="text-h2 font-semibold text-text-primary flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-sev-low shrink-0" />
              2. Nature of Reconnaissance & Safety Guarantees
            </h2>
            <p>
              PLIŌRA operates 100% agentless and safe reconnaissance:
            </p>
            <ul className="list-disc pl-6 space-y-1.5 text-text-secondary">
              <li>
                <strong>Passive Discovery:</strong> Certificate Transparency log lookups, public DNS zone records, WHOIS registry queries, and public code search.
              </li>
              <li>
                <strong>Non-Intrusive Probing:</strong> Standard HTTP GET/HEAD requests, TLS handshake cipher negotiation, and safe banner queries on authorized ports.
              </li>
              <li>
                <strong>Zero Exploitation:</strong> PLIŌRA does NOT execute exploit payloads, attempt brute-force password attacks, inject SQL/XSS vectors, or perform denial-of-service stress testing.
              </li>
            </ul>
          </section>

          {/* Section 3: Acceptable Use */}
          <section className="space-y-3">
            <h2 className="text-h2 font-semibold text-text-primary flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-sev-high shrink-0" />
              3. Acceptable Use Policy (AUP)
            </h2>
            <p>
              By utilizing PLIŌRA Threat Monitor, you agree not to:
            </p>
            <ul className="list-disc pl-6 space-y-1.5 text-text-secondary">
              <li>Initiate monitoring against domains or networks you do not own or possess explicit written authorization to monitor.</li>
              <li>Attempt to circumvent tenant isolation, API rate limits, or scan quotas.</li>
              <li>Use findings or threat intelligence for extortion, unlawful harassment, or unauthorized exploitation.</li>
              <li>Attempt to trigger Server-Side Request Forgery (SSRF) against internal, cloud-metadata, or private IP networks.</li>
            </ul>
          </section>

          {/* Section 4: Abuse Reporting */}
          <section className="space-y-3 p-5 rounded-xl border border-border bg-surface">
            <h2 className="text-h2 font-semibold text-text-primary flex items-center gap-2">
              <Mail className="w-5 h-5 text-accent shrink-0" />
              4. Third-Party Inquiries & Abuse Reporting
            </h2>
            <p>
              If you represent an external entity and believe an automated query originating from PLIŌRA infrastructure touched your systems in error, or if you wish to submit an abuse report:
            </p>
            <div className="font-mono text-body-sm text-text-primary bg-surface-raised p-3 rounded-lg border border-border flex items-center justify-between">
              <span>Contact: abuse@pliora.io (CC: security@pliora.io)</span>
              <span className="text-caption text-text-tertiary">SLA: &lt; 24h</span>
            </div>
            <p className="text-caption text-text-tertiary">
              Include the originating IP address, target host, timestamp (UTC), and observed request headers for immediate triage and domain suppression.
            </p>
          </section>

          {/* Section 5: Data Retention */}
          <section className="space-y-3">
            <h2 className="text-h2 font-semibold text-text-primary">
              5. Data & Evidence Retention Policy
            </h2>
            <p>
              To balance compliance auditing needs against storage hygiene, PLIŌRA maintains the following automated retention schedule:
            </p>
            <ul className="list-disc pl-6 space-y-1.5 text-text-secondary">
              <li>
                <strong>Raw Evidence Records:</strong> Retained for 90 days from collection. After 90 days, heavy observation payloads are automatically pruned while maintaining immutable SHA-256 hashes and finding history.
              </li>
              <li>
                <strong>Cancelled Accounts:</strong> When an account subscription terminates, existing monitored data enters a 30-day grace/retention window before automated purging.
              </li>
              <li>
                <strong>Audit Logs:</strong> Security audit logs (logins, scans, role mutations, billing changes) are retained for 365 days.
              </li>
            </ul>
          </section>

          {/* Section 6: Limitations */}
          <section className="space-y-3">
            <h2 className="text-h2 font-semibold text-text-primary">
              6. Service Guarantees & Disclaimers
            </h2>
            <p>
              PLIŌRA provides external attack surface monitoring based on publicly visible indicators. External monitoring cannot guarantee detection of internal network compromises, zero-day vulnerabilities in proprietary software, or lateral movement inside private perimeter defenses.
            </p>
          </section>
        </div>
      </main>

      <SiteFooter />
    </div>
  );
}
