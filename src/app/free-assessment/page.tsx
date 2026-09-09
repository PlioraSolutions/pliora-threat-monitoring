'use client';

import React, { useState, useEffect, useRef, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import {
  ArrowRight,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  ShieldCheck,
  Server,
  Lock,
  Globe,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react';

import { SiteHeader } from '@/components/SiteHeader';
import { SiteFooter } from '@/components/SiteFooter';
import { SeverityBadge } from '@/components/SeverityBadge';
import { EvidenceBlock } from '@/components/EvidenceBlock';
import { AiAnalystNote } from '@/components/AiAnalystNote';

interface AssessmentFinding {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM';
  asset: string;
  plainSummary: string;
  businessImpact: string;
  remediation: string;
  checkType: string;
  evidence: string;
}

interface AssessmentResult {
  success: boolean;
  domain: string;
  ip: string;
  allIps: string[];
  assetsEnumerated: number;
  discoveredAssets: string[];
  server: string;
  tls: {
    verified: boolean;
    issuer: string;
    validTo: string;
    protocol: string;
    cipher: string;
    daysRemaining: number;
    isExpired?: boolean;
  };
  securityPosture: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  findings: AssessmentFinding[];
  counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  scannedAt: string;
  error?: string;
}

const CHECKLIST_STEPS = [
  'Resolving DNS records & enumerating perimeter hosts...',
  'Performing TLS handshake & inspecting certificate chain...',
  'Auditing HTTP security headers (CSP, HSTS, clickjacking)...',
  'Validating email authentication records (SPF & DMARC policies)...',
];

function FreeAssessmentContent() {
  const searchParams = useSearchParams();
  const initialDomain = searchParams.get('domain') || '';

  const [domain, setDomain] = useState(initialDomain);
  const [isRunning, setIsRunning] = useState(false);
  const [stepIndex, setStepIndex] = useState(-1);
  const [hasResults, setHasResults] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [assessmentData, setAssessmentData] = useState<AssessmentResult | null>(null);
  const [findings, setFindings] = useState<AssessmentFinding[]>([]);
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);

  const stepIntervalRef = useRef<NodeJS.Timeout | null>(null);

  const cleanupInterval = () => {
    if (stepIntervalRef.current) {
      clearInterval(stepIntervalRef.current);
      stepIntervalRef.current = null;
    }
  };

  useEffect(() => {
    return () => cleanupInterval();
  }, []);

  const runAssessment = async (targetDomain: string) => {
    const clean = targetDomain
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '')
      .replace(/:\d+$/, '');

    if (!clean) return;

    cleanupInterval();
    setIsRunning(true);
    setHasResults(false);
    setScanError(null);
    setStepIndex(0);

    // Animate checklist steps while the actual live scan runs
    let currentStep = 0;
    stepIntervalRef.current = setInterval(() => {
      currentStep++;
      if (currentStep < CHECKLIST_STEPS.length) {
        setStepIndex(currentStep);
      }
    }, 600);

    try {
      const response = await fetch('/api/free-assessment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: clean }),
      });

      const data: AssessmentResult = await response.json();

      cleanupInterval();
      setStepIndex(CHECKLIST_STEPS.length);

      if (!response.ok || !data.success) {
        setScanError(data.error || 'Failed to complete perimeter assessment.');
        setIsRunning(false);
        return;
      }

      // Small delay so user sees all checkmarks complete
      setTimeout(() => {
        setAssessmentData(data);
        setFindings(data.findings || []);
        if (data.findings && data.findings.length > 0) {
          setExpandedFindingId(data.findings[0].id);
        } else {
          setExpandedFindingId(null);
        }
        setIsRunning(false);
        setHasResults(true);
      }, 300);
    } catch (err: any) {
      cleanupInterval();
      setScanError(err.message || 'Network error occurred while scanning perimeter.');
      setIsRunning(false);
    }
  };

  useEffect(() => {
    if (initialDomain && !hasResults && !isRunning) {
      runAssessment(initialDomain);
    }
  }, [initialDomain]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    runAssessment(domain);
  };

  const getGradeBadge = (grade: string) => {
    switch (grade) {
      case 'A':
        return 'bg-sev-low/15 text-sev-low border-sev-low/30';
      case 'B':
        return 'bg-accent/15 text-accent border-accent/30';
      case 'C':
        return 'bg-sev-medium/15 text-sev-medium border-sev-medium/30';
      case 'D':
        return 'bg-sev-high/15 text-sev-high border-sev-high/30';
      default:
        return 'bg-sev-critical/15 text-sev-critical border-sev-critical/30';
    }
  };

  return (
    <div className="max-w-[1200px] mx-auto px-6 py-12 sm:py-16 space-y-12">
      {/* Above the fold header */}
      <div className="max-w-[720px] mx-auto text-center space-y-4">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded border border-border bg-bg-raised text-[12px] font-mono text-text-secondary">
          <span className="w-1.5 h-1.5 rounded-full bg-accent"></span>
          Real-time non-invasive perimeter assessment
        </div>

        <h1 className="text-[32px] sm:text-[44px] font-semibold tracking-tight text-text-primary leading-tight">
          Run a free attack surface assessment.
        </h1>

        <p className="text-[16px] text-text-secondary leading-relaxed max-w-[52ch] mx-auto">
          Inspect any domain for exposed endpoints, missing transport security headers, and known perimeter vulnerabilities in real time.
        </p>

        {/* Focused Domain Input Form */}
        <form onSubmit={handleSubmit} className="pt-2 max-w-[560px] mx-auto">
          <div className="flex flex-col sm:flex-row gap-2">
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              className="flex-1 px-4 py-3 bg-bg-raised border border-border rounded-input text-[16px] font-mono text-text-primary placeholder-text-tertiary focus:outline-none focus:border-accent transition-colors"
              required
              disabled={isRunning}
            />
            <button
              type="submit"
              disabled={isRunning || !domain.trim()}
              className="px-6 py-3 rounded-btn bg-accent text-white text-[14px] font-medium hover:bg-accent-hover disabled:opacity-60 transition-colors duration-hover flex items-center justify-center gap-2"
            >
              {isRunning ? (
                <>
                  <RefreshCw size={16} className="animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <span>Run assessment</span>
                  <ArrowRight size={16} />
                </>
              )}
            </button>
          </div>
          <div className="pt-2 text-[12px] font-mono text-text-tertiary text-center sm:text-left">
            100% passive · Live DNS, TLS & HTTP inspection · Safe to scan any public domain
          </div>
        </form>
      </div>

      {/* Error state */}
      {scanError && (
        <div className="max-w-[700px] mx-auto p-5 border border-sev-critical/30 rounded-card bg-sev-critical-bg text-sev-critical flex items-start gap-3">
          <AlertCircle size={20} className="shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="font-semibold text-[15px]">Perimeter Scan Error</div>
            <div className="text-[14px] text-text-secondary leading-relaxed">{scanError}</div>
          </div>
        </div>
      )}

      {/* Sequential Checklist Animation */}
      {isRunning && (
        <div className="max-w-[700px] mx-auto border border-border rounded-card bg-bg-raised p-6 space-y-4 font-mono text-body-sm">
          <div className="flex items-center justify-between border-b border-border pb-2 text-caption text-text-tertiary">
            <span>Target: {domain}</span>
            <span className="text-accent animate-pulse font-medium">Executing live passive probes...</span>
          </div>

          <div className="space-y-3">
            {CHECKLIST_STEPS.map((step, idx) => {
              const isDone = stepIndex > idx;
              const isCurrent = stepIndex === idx;

              return (
                <div
                  key={step}
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
                  <span className="text-[14px]">{step}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Real Results Display */}
      {hasResults && assessmentData && (
        <div className="max-w-[900px] mx-auto space-y-6">
          {/* Summary Indicator Header */}
          <div className="p-6 border border-border rounded-card bg-bg-raised space-y-5">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-4">
              <div className="space-y-1">
                <div className="text-caption font-mono text-text-tertiary uppercase tracking-wider">
                  Live Perimeter Assessment
                </div>
                <h2 className="text-[20px] sm:text-[24px] font-semibold text-text-primary">
                  Perimeter report for <span className="font-mono text-accent">{assessmentData.domain}</span>
                </h2>
                <p className="text-[14px] text-text-secondary">
                  {findings.length === 0
                    ? 'No critical, high, or medium security exposures were detected on this target.'
                    : `${findings.length} security finding${findings.length > 1 ? 's' : ''} require review and remediation.`}
                </p>
              </div>

              {/* Severity Count Pills */}
              <div className="flex items-center gap-2 font-mono text-caption flex-wrap">
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-sev-critical-bg text-sev-critical font-medium">
                  <span>{assessmentData.counts.critical}</span> Critical
                </span>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-sev-high-bg text-sev-high font-medium">
                  <span>{assessmentData.counts.high}</span> High
                </span>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-sev-medium-bg text-sev-medium font-medium">
                  <span>{assessmentData.counts.medium}</span> Medium
                </span>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-sev-low-bg text-sev-low font-medium">
                  <span>{assessmentData.counts.low}</span> Low
                </span>
              </div>
            </div>

            {/* Real Infrastructure Details Bar */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-caption font-mono">
              <div className="p-3 bg-surface border border-border rounded">
                <div className="text-text-tertiary flex items-center gap-1.5 mb-1">
                  <Globe size={13} className="text-accent" />
                  <span>Primary IP</span>
                </div>
                <div className="text-text-primary font-semibold truncate">{assessmentData.ip}</div>
              </div>

              <div className="p-3 bg-surface border border-border rounded">
                <div className="text-text-tertiary flex items-center gap-1.5 mb-1">
                  <Server size={13} className="text-accent" />
                  <span>Server Stack</span>
                </div>
                <div className="text-text-primary font-semibold truncate">{assessmentData.server}</div>
              </div>

              <div className="p-3 bg-surface border border-border rounded">
                <div className="text-text-tertiary flex items-center gap-1.5 mb-1">
                  <Lock size={13} className="text-accent" />
                  <span>TLS Issuer</span>
                </div>
                <div className="text-text-primary font-semibold truncate">{assessmentData.tls.issuer}</div>
              </div>

              <div className="p-3 bg-surface border border-border rounded">
                <div className="text-text-tertiary flex items-center gap-1.5 mb-1">
                  <ShieldCheck size={13} className="text-accent" />
                  <span>Posture Score</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-text-primary font-semibold">{assessmentData.securityPosture}/100</span>
                  <span className={`px-1.5 py-0.5 rounded border text-[11px] font-bold ${getGradeBadge(assessmentData.grade)}`}>
                    Grade {assessmentData.grade}
                  </span>
                </div>
              </div>
            </div>

            {/* Discovered Assets & Action */}
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-caption text-text-secondary pt-1">
              <div className="font-mono text-[12px]">
                Enumerated {assessmentData.assetsEnumerated} perimeter endpoint{assessmentData.assetsEnumerated > 1 ? 's' : ''}:{' '}
                <span className="text-text-primary">{assessmentData.discoveredAssets.join(', ')}</span>
              </div>
              <Link
                href="/dashboard"
                className="px-4 py-1.5 rounded-btn bg-accent text-white font-medium hover:bg-accent-hover transition-colors duration-hover inline-flex items-center gap-1.5 shrink-0"
              >
                <span>Track in console</span>
                <ArrowRight size={14} />
              </Link>
            </div>
          </div>

          {/* Clean State (No Findings) */}
          {findings.length === 0 && (
            <div className="p-8 border border-border rounded-card bg-bg-raised text-center space-y-3">
              <div className="w-12 h-12 rounded-full bg-sev-low/15 text-sev-low flex items-center justify-center mx-auto">
                <CheckCircle2 size={24} />
              </div>
              <h3 className="text-[18px] font-semibold text-text-primary">
                Perimeter Verified — Clean Posture
              </h3>
              <p className="text-[14px] text-text-secondary max-w-[54ch] mx-auto">
                No high or critical vulnerabilities were found on {assessmentData.domain}. Transport encryption,
                essential response headers, and email authentication are aligned with baseline industry standards.
              </p>
            </div>
          )}

          {/* Real Grounded Findings List */}
          {findings.length > 0 && (
            <div className="space-y-3">
              <div className="text-caption font-mono text-text-tertiary uppercase tracking-wider px-1">
                Detected Perimeter Findings ({findings.length})
              </div>

              {findings.map((finding) => {
                const isExpanded = expandedFindingId === finding.id;

                return (
                  <div
                    key={finding.id}
                    className="border border-border rounded-card bg-bg-raised transition-colors overflow-hidden"
                  >
                    {/* Row Header / Toggle */}
                    <button
                      type="button"
                      onClick={() => setExpandedFindingId(isExpanded ? null : finding.id)}
                      className="w-full p-5 flex items-start sm:items-center justify-between gap-4 text-left hover:bg-surface/50 transition-colors"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                        <SeverityBadge severity={finding.severity} />
                        <div>
                          <h3 className="text-[15px] font-semibold text-text-primary">
                            {finding.title}
                          </h3>
                          <div className="flex items-center gap-2 text-caption font-mono text-text-tertiary pt-0.5">
                            <span>{finding.id}</span>
                            <span>·</span>
                            <span>Asset: {finding.asset}</span>
                            <span>·</span>
                            <span className="text-sev-low">{finding.confidence}</span>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 text-caption text-text-tertiary font-mono shrink-0">
                        <span className="hidden sm:inline">
                          {isExpanded ? 'Hide evidence' : 'View evidence'}
                        </span>
                        {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                      </div>
                    </button>

                    {/* Expandable Plain Language & Evidence Block */}
                    {isExpanded && (
                      <div className="px-5 pb-5 pt-2 border-t border-border space-y-4">
                        {/* Grounded Explanation */}
                        <AiAnalystNote
                          summary={finding.plainSummary}
                          impact={finding.businessImpact}
                          recommendedAction={finding.remediation}
                        />

                        {/* Raw Immutable Evidence */}
                        <EvidenceBlock
                          checkType={finding.checkType}
                          rawSignal={finding.evidence}
                          observedAt={assessmentData.scannedAt}
                        />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* Continuous Monitoring Callout */}
          <div className="border border-border rounded-card bg-surface p-6 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="space-y-1">
              <h3 className="text-[16px] font-semibold text-text-primary">
                Never miss an exposed asset again.
              </h3>
              <p className="text-[14px] text-text-secondary">
                Set up automated continuous monitoring for <span className="font-mono text-accent">{assessmentData.domain}</span> to receive instant alerts whenever new subdomains, typosquats, or SSL issues arise.
              </p>
            </div>
            <Link
              href="/dashboard"
              className="px-5 py-2.5 rounded-btn bg-accent text-white text-[14px] font-medium hover:bg-accent-hover transition-colors duration-hover whitespace-nowrap shrink-0"
            >
              Start monitoring for free
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}

export default function FreeAssessmentPage() {
  return (
    <div className="min-h-screen bg-bg text-text-primary selection:bg-accent-muted selection:text-text-primary">
      <SiteHeader />
      <Suspense fallback={<div className="p-12 text-center text-text-tertiary">Loading assessment module...</div>}>
        <FreeAssessmentContent />
      </Suspense>
      <SiteFooter />
    </div>
  );
}
