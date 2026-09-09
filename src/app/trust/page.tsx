'use client';

import React from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  Lock,
  Database,
  Cpu,
  Fingerprint,
  FileCheck2,
  AlertOctagon,
  ArrowLeft,
  ExternalLink,
} from 'lucide-react';
import { SiteHeader } from '@/components/SiteHeader';
import { SiteFooter } from '@/components/SiteFooter';

export default function TrustPage() {
  return (
    <div className="min-h-screen bg-bg text-text-primary flex flex-col transition-colors">
      <SiteHeader />

      <main className="flex-1 max-w-[1000px] w-full mx-auto px-6 py-16">
        <Link
          href="/"
          className="inline-flex items-center gap-2 text-caption text-text-secondary hover:text-text-primary transition-colors mb-8"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Home</span>
        </Link>

        {/* Hero */}
        <div className="space-y-4 mb-16 border-b border-border pb-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-border bg-surface text-caption text-accent font-medium">
            <ShieldCheck className="w-4 h-4 text-accent" />
            <span>Security Architecture & Trust Signals</span>
          </div>
          <h1 className="text-display font-semibold tracking-tight text-text-primary">
            Security, Privacy & Architecture at PLIŌRA
          </h1>
          <p className="text-body text-text-secondary max-w-[70ch] leading-relaxed">
            External attack surface monitoring requires deep trust. We believe in defense-in-depth, verifiable cryptographic guarantees, and complete transparency about how we discover, handle, and protect your security data.
          </p>
        </div>

        {/* 6 Core Trust Pillars Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-16">
          {/* Pillar 1: Anti-SSRF Defense */}
          <div className="p-6 rounded-xl border border-border bg-surface space-y-3">
            <div className="w-10 h-10 rounded-lg bg-accent/10 border border-accent/20 flex items-center justify-center text-accent">
              <AlertOctagon className="w-5 h-5" />
            </div>
            <h2 className="text-h2 font-semibold text-text-primary">
              Hardened Anti-SSRF Socket Layer
            </h2>
            <p className="text-body-sm text-text-secondary leading-relaxed">
              Every outbound probe executes through a pre-flight DNS pinning engine (<code className="font-mono text-[12px] bg-surface-raised px-1 py-0.5 rounded">assertSafeTargetHostname</code>). We immediately abort any socket targeting loopback (<code className="font-mono text-[12px] bg-surface-raised px-1 py-0.5 rounded">127.0.0.1</code>), cloud metadata (<code className="font-mono text-[12px] bg-surface-raised px-1 py-0.5 rounded">169.254.169.254</code>), or private RFC 1918 subnets (<code className="font-mono text-[12px] bg-surface-raised px-1 py-0.5 rounded">10.0.0.0/8</code>, <code className="font-mono text-[12px] bg-surface-raised px-1 py-0.5 rounded">172.16.0.0/12</code>, <code className="font-mono text-[12px] bg-surface-raised px-1 py-0.5 rounded">192.168.0.0/16</code>).
            </p>
          </div>

          {/* Pillar 2: Multi-Tenant Isolation */}
          <div className="p-6 rounded-xl border border-border bg-surface space-y-3">
            <div className="w-10 h-10 rounded-lg bg-sev-low/10 border border-sev-low/20 flex items-center justify-center text-sev-low">
              <Lock className="w-5 h-5" />
            </div>
            <h2 className="text-h2 font-semibold text-text-primary">
              Cryptographic Multi-Tenant Isolation
            </h2>
            <p className="text-body-sm text-text-secondary leading-relaxed">
              Data isolation is enforced strictly at the database query layer. Every API key (<code className="font-mono text-[12px] bg-surface-raised px-1 py-0.5 rounded">plk_live_...</code>) is SHA-256 hashed and bound to an immutable organization identifier. Cross-tenant access attempts return HTTP 404 to eliminate resource enumeration vectors.
            </p>
          </div>

          {/* Pillar 3: Evidence Provenance */}
          <div className="p-6 rounded-xl border border-border bg-surface space-y-3">
            <div className="w-10 h-10 rounded-lg bg-accent/10 border border-accent/20 flex items-center justify-center text-accent">
              <Fingerprint className="w-5 h-5" />
            </div>
            <h2 className="text-h2 font-semibold text-text-primary">
              Cryptographic Evidence Chain-of-Custody
            </h2>
            <p className="text-body-sm text-text-secondary leading-relaxed">
              Every raw observation (DNS records, TLS certificates, service banners, HTTP headers) is computed with an immutable SHA-256 content hash upon capture. Security findings link back directly to this verifiable chain of evidence—zero speculative or fabricated reports.
            </p>
          </div>

          {/* Pillar 4: Confidence-Gating */}
          <div className="p-6 rounded-xl border border-border bg-surface space-y-3">
            <div className="w-10 h-10 rounded-lg bg-sev-medium/10 border border-sev-medium/20 flex items-center justify-center text-sev-medium">
              <FileCheck2 className="w-5 h-5" />
            </div>
            <h2 className="text-h2 font-semibold text-text-primary">
              Deterministic Confidence-Gating
            </h2>
            <p className="text-body-sm text-text-secondary leading-relaxed">
              We apply strict confidence ceilings across all 18 scan plugins. Uncorroborated banner fingerprints are hard-capped at MEDIUM confidence. Only independently verified CVE signatures, verified takeover proofs, or multi-source evidence reach HIGH or CRITICAL confidence.
            </p>
          </div>

          {/* Pillar 5: Grounded AI Security Analyst */}
          <div className="p-6 rounded-xl border border-border bg-surface space-y-3">
            <div className="w-10 h-10 rounded-lg bg-accent/10 border border-accent/20 flex items-center justify-center text-accent">
              <Cpu className="w-5 h-5" />
            </div>
            <h2 className="text-h2 font-semibold text-text-primary">
              Grounded AI & Anti-Hallucination Bounds
            </h2>
            <p className="text-body-sm text-text-secondary leading-relaxed">
              Our AI narrative engine strictly cites verified evidence fields. If an LLM attempts to claim an ungrounded port number, hallucinate an external IP address, or inflate severity, our post-generation validator automatically rejects the response and activates a deterministic fallback template.
            </p>
          </div>

          {/* Pillar 6: Secrets Management & Redaction */}
          <div className="p-6 rounded-xl border border-border bg-surface space-y-3">
            <div className="w-10 h-10 rounded-lg bg-sev-low/10 border border-sev-low/20 flex items-center justify-center text-sev-low">
              <Database className="w-5 h-5" />
            </div>
            <h2 className="text-h2 font-semibold text-text-primary">
              Automated Secrets Redaction & Zero Leaks
            </h2>
            <p className="text-body-sm text-text-secondary leading-relaxed">
              Customer credentials, Stripe secret keys, bearer tokens, and database connection strings are protected by automated redaction filters across all loggers, error traces, and telemetry pipelines. All data is encrypted in transit via TLS 1.3 and at rest with AES-256.
            </p>
          </div>
        </div>

        {/* Compliance Roadmap & SOC 2 Status */}
        <div className="p-8 rounded-xl border border-border bg-surface space-y-6 mb-16">
          <div className="space-y-2">
            <h2 className="text-h1 font-semibold text-text-primary">
              Compliance & SOC 2 Roadmap
            </h2>
            <p className="text-body text-text-secondary leading-relaxed">
              PLIŌRA is built with SOC 2 Trust Services Criteria (Security, Availability, Confidentiality) embedded directly into our software design.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
            <div className="p-4 rounded-lg bg-surface-raised border border-border space-y-1">
              <div className="text-caption font-semibold text-sev-low uppercase tracking-wider">
                Phase 1: Complete
              </div>
              <div className="text-body font-medium text-text-primary">
                Technical Controls & Audit Logs
              </div>
              <p className="text-caption text-text-tertiary">
                Audit logging for all authentication, scans, alerts, and billing events.
              </p>
            </div>

            <div className="p-4 rounded-lg bg-surface-raised border border-border space-y-1">
              <div className="text-caption font-semibold text-accent uppercase tracking-wider">
                Phase 2: In Progress
              </div>
              <div className="text-body font-medium text-text-primary">
                Observability & Retention
              </div>
              <p className="text-caption text-text-tertiary">
                Automated 90-day evidence lifecycle, structured error reporting, and CI/CD gates.
              </p>
            </div>

            <div className="p-4 rounded-lg bg-surface-raised border border-border space-y-1">
              <div className="text-caption font-semibold text-text-secondary uppercase tracking-wider">
                Phase 3: Formal Audit
              </div>
              <div className="text-body font-medium text-text-primary">
                Type I & Type II Attestation
              </div>
              <p className="text-caption text-text-tertiary">
                Formal external independent audit scheduled upon customer volume milestone.
              </p>
            </div>
          </div>
        </div>

        {/* Vulnerability Disclosure Contact */}
        <div className="p-6 rounded-xl border border-border bg-surface-raised flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="text-body font-semibold text-text-primary">
              Have questions or discovered a security issue?
            </div>
            <p className="text-body-sm text-text-secondary">
              We operate a coordinated vulnerability disclosure policy with a 24-hour initial response SLA.
            </p>
          </div>
          <a
            href="mailto:security@pliora.io"
            className="px-4 py-2 rounded-lg bg-accent hover:bg-accent-hover text-white font-medium text-body-sm transition-colors shrink-0"
          >
            Contact Security Team
          </a>
        </div>
      </main>

      <SiteFooter />
    </div>
  );
}
