'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import {
  Shield,
  AlertTriangle,
  ArrowRight,
  FileText,
  Download,
  PlusCircle,
  RefreshCw,
  Loader2,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/client/api';
import { RiskScoreHero } from '@/components/RiskScoreHero';
import { RiskTrendChart } from '@/components/RiskTrendChart';
import { SeverityBadge } from '@/components/SeverityBadge';
import { ConfidenceBadge } from '@/components/ConfidenceBadge';
import { EvidenceDrawer, FindingDetailItem } from '@/components/EvidenceDrawer';
import { ExecutiveSummaryModal } from '@/components/ExecutiveSummaryModal';

export default function DashboardHomePage() {
  const { user, organization, role } = useAuth();

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Real data feeds
  const [riskData, setRiskData] = useState<any>(null);
  const [riskHistory, setRiskHistory] = useState<any[]>([]);
  const [topFindings, setTopFindings] = useState<FindingDetailItem[]>([]);
  const [allOpenFindings, setAllOpenFindings] = useState<any[]>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const [activeScan, setActiveScan] = useState<any>(null);

  // Modals & Drawers
  const [selectedFinding, setSelectedFinding] = useState<FindingDetailItem | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [execSummaryOpen, setExecSummaryOpen] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  const fetchDashboardData = useCallback(async () => {
    try {
      const [scoreRes, historyRes, findingsRes, assetsRes, scansRes] = await Promise.allSettled([
        api.get('/api/risk-score'),
        api.get('/api/risk-score/history'),
        api.get('/api/findings', { params: { status: 'OPEN', sortBy: 'riskScore', sortOrder: 'desc', limit: 10 } }),
        api.get('/api/assets'),
        api.get('/api/scans'),
      ]);

      if (scoreRes.status === 'fulfilled') {
        setRiskData(scoreRes.value);
      }
      if (historyRes.status === 'fulfilled') {
        setRiskHistory(Array.isArray(historyRes.value) ? historyRes.value : historyRes.value?.data || []);
      }
      if (findingsRes.status === 'fulfilled') {
        const list = findingsRes.value?.data || (Array.isArray(findingsRes.value) ? findingsRes.value : []);
        setTopFindings(list.slice(0, 5));
        setAllOpenFindings(list);
      }
      if (assetsRes.status === 'fulfilled') {
        setAssets(Array.isArray(assetsRes.value) ? assetsRes.value : assetsRes.value?.data || []);
      }
      if (scansRes.status === 'fulfilled') {
        const scansList = Array.isArray(scansRes.value) ? scansRes.value : scansRes.value?.data || [];
        const running = scansList.find((s: any) => s.status === 'ACTIVE' || s.status === 'QUEUED');
        setActiveScan(running || null);
      }
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  // Polling for active scan if running
  useEffect(() => {
    if (!activeScan) return;
    const interval = setInterval(async () => {
      try {
        const scans = await api.get('/api/scans');
        const list = Array.isArray(scans) ? scans : scans?.data || [];
        const running = list.find((s: any) => s.status === 'ACTIVE' || s.status === 'QUEUED');
        setActiveScan(running || null);
        if (!running) {
          // Scan finished, refresh dashboard numbers
          fetchDashboardData();
        }
      } catch {}
    }, 3000);

    return () => clearInterval(interval);
  }, [activeScan, fetchDashboardData]);

  const handleManualRefresh = () => {
    setRefreshing(true);
    fetchDashboardData();
  };

  const handleFindingClick = (f: FindingDetailItem) => {
    setSelectedFinding(f);
    setDrawerOpen(true);
  };

  const handleFindingStatusUpdate = async (newStatus: 'OPEN' | 'RESOLVED' | 'ACCEPTED_RISK') => {
    if (!selectedFinding) return;
    try {
      await api.patch(`/api/findings/${selectedFinding.id}`, { status: newStatus });
      setDrawerOpen(false);
      setSelectedFinding(null);
      await fetchDashboardData();
    } catch (err: any) {
      alert(`Could not update finding: ${err.message}`);
    }
  };

  const handleDownloadPdf = async () => {
    try {
      setDownloadingPdf(true);
      const res = await fetch('/api/reports/executive-summary/pdf');
      if (!res.ok) throw new Error(`Server returned status ${res.status}`);
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `pliora-security-report-${organization?.slug || 'report'}-${new Date().toISOString().split('T')[0]}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(`Failed to download PDF report: ${err.message}`);
    } finally {
      setDownloadingPdf(false);
    }
  };

  // Severity counts
  const severityCounts = {
    CRITICAL: allOpenFindings.filter((f) => f.severity === 'CRITICAL').length,
    HIGH: allOpenFindings.filter((f) => f.severity === 'HIGH').length,
    MEDIUM: allOpenFindings.filter((f) => f.severity === 'MEDIUM').length,
    LOW: allOpenFindings.filter((f) => f.severity === 'LOW').length,
  };

  if (loading) {
    return (
      <div className="py-16 flex flex-col items-center justify-center space-y-4">
        <Loader2 className="w-8 h-8 text-accent animate-spin" />
        <p className="text-caption text-text-secondary">Loading organizational risk posture...</p>
      </div>
    );
  }

  const hasAssets = assets.length > 0;
  const currentScore = riskData?.riskScore ?? 0;

  return (
    <div className="space-y-8">
      {/* Top Header & Action Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-text-primary">
            Security Command Center
          </h1>
          <p className="text-caption text-text-secondary mt-0.5">
            Real-time exposure posture and prioritized remediation actions for {organization?.name}.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleManualRefresh}
            disabled={refreshing}
            className="px-3.5 py-2 rounded-lg bg-surface border border-border hover:bg-surface-raised text-text-secondary hover:text-text-primary text-caption font-medium transition-colors flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          <button
            onClick={() => setExecSummaryOpen(true)}
            className="px-3.5 py-2 rounded-lg bg-surface border border-border hover:bg-surface-raised text-text-primary text-caption font-semibold transition-colors flex items-center gap-1.5 shadow-sm"
          >
            <FileText className="w-4 h-4 text-accent" />
            <span>Executive Summary</span>
          </button>

          <button
            onClick={handleDownloadPdf}
            disabled={downloadingPdf}
            className="px-3.5 py-2 rounded-lg bg-surface border border-border hover:bg-surface-raised text-text-primary text-caption font-semibold transition-colors flex items-center gap-1.5 shadow-sm"
          >
            {downloadingPdf ? (
              <Loader2 className="w-4 h-4 text-accent animate-spin" />
            ) : (
              <Download className="w-4 h-4 text-accent" />
            )}
            <span>Export PDF</span>
          </button>

          <Link
            href="/onboarding"
            className="px-4 py-2 rounded-lg bg-accent hover:bg-accent-hover text-white text-caption font-semibold transition-colors flex items-center gap-1.5 shadow-sm"
          >
            <PlusCircle className="w-4 h-4" />
            <span>Add Domain</span>
          </Link>
        </div>
      </div>

      {/* Active Scan Progress Banner */}
      {activeScan && (
        <div className="bg-accent/10 border border-accent/30 rounded-xl p-4 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Loader2 className="w-5 h-5 text-accent animate-spin shrink-0" />
            <div>
              <div className="text-body font-semibold text-text-primary">
                Security Scan in Progress
              </div>
              <div className="text-caption text-text-secondary">
                Analyzing target asset: <strong className="font-mono text-text-primary">{activeScan.targetFqdn || activeScan.targetAssetId}</strong>
              </div>
            </div>
          </div>

          <div className="w-48 text-right space-y-1">
            <div className="text-caption font-mono text-text-primary">
              {activeScan.progress || 0}% Complete
            </div>
            <div className="h-2 w-full bg-surface-overlay rounded-full overflow-hidden">
              <div
                className="h-full bg-accent transition-all duration-300 rounded-full"
                style={{ width: `${activeScan.progress || 10}%` }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Zero Assets Onboarding Prompt */}
      {!hasAssets && (
        <div className="bg-surface border-2 border-dashed border-border rounded-xl p-8 text-center space-y-4">
          <div className="w-12 h-12 rounded-full bg-accent/10 text-accent mx-auto flex items-center justify-center">
            <Shield className="w-6 h-6" />
          </div>
          <div className="max-w-md mx-auto space-y-1">
            <h2 className="text-lg font-bold text-text-primary">Welcome to PLIŌRA Threat Monitor</h2>
            <p className="text-caption text-text-secondary">
              Get started by adding your organization's primary domain. Our passive discovery and exposure analyzers will map your attack surface.
            </p>
          </div>
          <Link
            href="/onboarding"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-accent text-white font-semibold text-body hover:bg-accent-hover transition-colors shadow"
          >
            <PlusCircle className="w-4 h-4" />
            <span>Add & Verify Your First Domain</span>
          </Link>
        </div>
      )}

      {/* Grid: Risk Score Dial & Trend Line */}
      {hasAssets && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <RiskScoreHero
              score={currentScore}
              letterGrade={riskData?.letterGrade}
              posture={riskData?.overallPosture}
              verdict={riskData?.verdict}
              contributingFindingsCount={allOpenFindings.length}
            />
          </div>

          <div className="lg:col-span-1">
            <RiskTrendChart history={riskHistory} />
          </div>
        </div>
      )}

      {/* Severity Breakdown Cards */}
      {hasAssets && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="bg-surface border border-border rounded-card p-4 space-y-1">
            <div className="text-caption font-semibold text-sev-critical flex items-center justify-between">
              <span>Critical Risk</span>
              <span className="w-2 h-2 rounded-full bg-sev-critical" />
            </div>
            <div className="text-3xl font-bold text-text-primary">{severityCounts.CRITICAL}</div>
            <div className="text-[11px] text-text-tertiary">Immediate action required</div>
          </div>

          <div className="bg-surface border border-border rounded-card p-4 space-y-1">
            <div className="text-caption font-semibold text-sev-high flex items-center justify-between">
              <span>High Risk</span>
              <span className="w-2 h-2 rounded-full bg-sev-high" />
            </div>
            <div className="text-3xl font-bold text-text-primary">{severityCounts.HIGH}</div>
            <div className="text-[11px] text-text-tertiary">Corroborated exposure</div>
          </div>

          <div className="bg-surface border border-border rounded-card p-4 space-y-1">
            <div className="text-caption font-semibold text-sev-medium flex items-center justify-between">
              <span>Medium Risk</span>
              <span className="w-2 h-2 rounded-full bg-sev-medium" />
            </div>
            <div className="text-3xl font-bold text-text-primary">{severityCounts.MEDIUM}</div>
            <div className="text-[11px] text-text-tertiary">Configuration drift</div>
          </div>

          <div className="bg-surface border border-border rounded-card p-4 space-y-1">
            <div className="text-caption font-semibold text-sev-low flex items-center justify-between">
              <span>Low / Info</span>
              <span className="w-2 h-2 rounded-full bg-sev-low" />
            </div>
            <div className="text-3xl font-bold text-text-primary">{severityCounts.LOW}</div>
            <div className="text-[11px] text-text-tertiary">Best practice hygiene</div>
          </div>
        </div>
      )}

      {/* Top 3-5 Issues to Fix First */}
      {hasAssets && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-text-primary">
                Top Issues to Fix First
              </h2>
              <p className="text-caption text-text-secondary">
                Ranked by calculated risk impact (Severity × Exposure × Confidence × Importance).
              </p>
            </div>

            <Link
              href="/findings"
              className="text-caption font-semibold text-accent hover:underline flex items-center gap-1"
            >
              <span>View all findings ({allOpenFindings.length})</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {topFindings.length === 0 ? (
            <div className="bg-surface border border-border rounded-card p-8 text-center space-y-2">
              <CheckCircle2 className="w-8 h-8 text-sev-low mx-auto" />
              <div className="text-body font-semibold text-text-primary">No open vulnerabilities</div>
              <p className="text-caption text-text-secondary">
                All discovered assets currently pass baseline configuration and exposure checks.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {topFindings.map((finding) => (
                <div
                  key={finding.id}
                  onClick={() => handleFindingClick(finding)}
                  className="bg-surface border border-border hover:border-accent/40 rounded-card p-4 transition-all duration-150 cursor-pointer shadow-sm hover:shadow flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                >
                  <div className="space-y-1.5 flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={finding.severity} />
                      <ConfidenceBadge confidence={finding.confidence} />
                      <span className="text-caption font-mono text-text-tertiary">
                        {finding.assetFqdn}
                      </span>
                    </div>

                    <h3 className="text-body font-semibold text-text-primary truncate">
                      {finding.title}
                    </h3>

                    <p className="text-caption text-text-secondary line-clamp-1">
                      {finding.summary}
                    </p>
                  </div>

                  <div className="flex items-center justify-between sm:justify-end gap-4 shrink-0 pt-2 sm:pt-0 border-t sm:border-t-0 border-border">
                    <div className="text-right">
                      <div className="text-[11px] text-text-tertiary font-medium uppercase tracking-wider">
                        Risk Score
                      </div>
                      <div className="text-xl font-bold text-text-primary">
                        {finding.riskScore}
                        <span className="text-caption text-text-tertiary font-normal"> / 100</span>
                      </div>
                    </div>

                    <button
                      type="button"
                      className="px-3.5 py-1.5 rounded-lg bg-surface-raised hover:bg-surface-overlay text-caption font-semibold text-text-primary border border-border transition-colors"
                    >
                      Inspect & Fix
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Drawer for Finding Detail & AI Explanation */}
      <EvidenceDrawer
        finding={selectedFinding}
        isOpen={drawerOpen}
        onClose={() => {
          setDrawerOpen(false);
          setSelectedFinding(null);
        }}
        onStatusChange={handleFindingStatusUpdate}
        userRole={role || 'MEMBER'}
      />

      {/* Executive Summary Modal */}
      <ExecutiveSummaryModal
        isOpen={execSummaryOpen}
        onClose={() => setExecSummaryOpen(false)}
      />
    </div>
  );
}
