'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  AlertTriangle,
  Search,
  Filter,
  RefreshCw,
  Loader2,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Shield,
  Layers,
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/client/api';
import { SeverityBadge } from '@/components/SeverityBadge';
import { ConfidenceBadge } from '@/components/ConfidenceBadge';
import { StatusBadge } from '@/components/StatusBadge';
import { EvidenceDrawer, FindingDetailItem } from '@/components/EvidenceDrawer';

export default function FindingsPage() {
  const { role } = useAuth();
  const isViewer = role === 'VIEWER';

  const [findings, setFindings] = useState<FindingDetailItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Selected finding drawer
  const [selectedFinding, setSelectedFinding] = useState<FindingDetailItem | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Filters & Pagination
  const [statusFilter, setStatusFilter] = useState<'OPEN' | 'RESOLVED' | 'ACCEPTED_RISK' | 'ALL'>('OPEN');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [confidenceFilter, setConfidenceFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCount, setTotalCount] = useState(0);

  // What-If Simulation State
  const [simulation, setSimulation] = useState<{
    scoreDelta: number;
    postureDelta: number;
    current: { score: number; securityPosture: number; grade: string };
    simulated: { score: number; securityPosture: number; grade: string };
    gradeChange: { from: string; to: string };
    resolvedFindingCount: number;
  } | null>(null);

  const fetchSimulation = useCallback(async (openFindingIds: string[]) => {
    if (!openFindingIds || openFindingIds.length === 0) {
      setSimulation(null);
      return;
    }
    try {
      const res = await api.post('/api/risk-score/simulate', { findingIds: openFindingIds });
      if (res?.success && res.data) {
        setSimulation(res.data);
      }
    } catch (err) {
      // Non-blocking for simulation UI
    }
  }, []);

  const fetchFindings = useCallback(async () => {
    try {
      const params: Record<string, any> = {
        page,
        limit: 15,
        sortBy: 'riskScore',
        sortOrder: 'desc',
      };

      if (statusFilter !== 'ALL') params.status = statusFilter;
      if (severityFilter !== 'ALL') params.severity = severityFilter;
      if (confidenceFilter !== 'ALL') params.confidence = confidenceFilter;

      const res = await api.get('/api/findings', { params });
      const list = res?.data || (Array.isArray(res) ? res : []);
      setFindings(list);
      setTotalPages(res?.pagination?.totalPages || 1);
      setTotalCount(res?.pagination?.total || list.length);

      const openIds = list.filter((f: any) => f.status === 'OPEN').map((f: any) => f.id);
      fetchSimulation(openIds);
    } catch (err) {
      console.error('Failed to load findings:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [page, statusFilter, severityFilter, confidenceFilter]);

  useEffect(() => {
    fetchFindings();
  }, [fetchFindings]);

  const handleRowClick = (f: FindingDetailItem) => {
    setSelectedFinding(f);
    setDrawerOpen(true);
  };

  const handleStatusChange = async (newStatus: 'OPEN' | 'RESOLVED' | 'ACCEPTED_RISK') => {
    if (!selectedFinding || isViewer) return;
    try {
      await api.patch(`/api/findings/${selectedFinding.id}`, { status: newStatus });
      setDrawerOpen(false);
      setSelectedFinding(null);
      await fetchFindings();
    } catch (err: any) {
      alert(`Could not update finding: ${err.message}`);
    }
  };

  const filteredFindings = findings.filter((f) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      f.title.toLowerCase().includes(q) ||
      f.assetFqdn.toLowerCase().includes(q) ||
      f.category.toLowerCase().includes(q) ||
      f.findingCode.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-text-primary">
            Findings & Triage
          </h1>
          <p className="text-caption text-text-secondary mt-0.5">
            Verified exposures and configuration defects prioritized by calculated risk impact.
          </p>
        </div>

        <button
          onClick={() => {
            setRefreshing(true);
            fetchFindings();
          }}
          disabled={refreshing}
          className="px-3.5 py-2 rounded-lg bg-surface border border-border hover:bg-surface-raised text-text-secondary hover:text-text-primary text-caption font-medium transition-colors flex items-center gap-1.5"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Status Filter Tabs */}
      <div className="flex items-center gap-2 border-b border-border pb-2">
        {(['OPEN', 'RESOLVED', 'ACCEPTED_RISK', 'ALL'] as const).map((st) => (
          <button
            key={st}
            onClick={() => {
              setStatusFilter(st);
              setPage(1);
            }}
            className={`px-3.5 py-1.5 rounded-lg text-caption font-semibold transition-colors ${
              statusFilter === st
                ? 'bg-accent text-white shadow-sm'
                : 'text-text-secondary hover:text-text-primary hover:bg-surface-raised'
            }`}
          >
            {st === 'ALL'
              ? 'All Findings'
              : st === 'OPEN'
              ? 'Open Issues'
              : st === 'RESOLVED'
              ? 'Resolved'
              : 'Risk Accepted'}
          </button>
        ))}
      </div>

      {/* Filter Toolbar */}
      <div className="bg-surface border border-border rounded-xl p-4 flex flex-wrap items-center justify-between gap-4 shadow-sm">
        {/* Search */}
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-text-tertiary absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by title, asset, or finding code..."
            className="w-full pl-9 pr-4 py-2 bg-surface-raised border border-border rounded-lg text-body text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none transition-colors"
          />
        </div>

        {/* Dropdowns */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Severity */}
          <div className="flex items-center gap-1.5">
            <span className="text-caption text-text-tertiary font-medium">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setPage(1);
              }}
              className="px-3 py-1.5 bg-surface-raised border border-border rounded-lg text-caption text-text-primary focus:border-accent focus:outline-none"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFORMATIONAL">Informational</option>
            </select>
          </div>

          {/* Confidence */}
          <div className="flex items-center gap-1.5">
            <span className="text-caption text-text-tertiary font-medium">Confidence:</span>
            <select
              value={confidenceFilter}
              onChange={(e) => {
                setConfidenceFilter(e.target.value);
                setPage(1);
              }}
              className="px-3 py-1.5 bg-surface-raised border border-border rounded-lg text-caption text-text-primary focus:border-accent focus:outline-none"
            >
              <option value="ALL">All Confidence</option>
              <option value="CONFIRMED">Confirmed</option>
              <option value="HIGH">High Confidence</option>
              <option value="MEDIUM">Medium Confidence</option>
              <option value="LOW">Low Confidence</option>
            </select>
          </div>
        </div>
      </div>

      {/* What-If Simulation Banner */}
      {simulation && simulation.resolvedFindingCount > 0 && statusFilter === 'OPEN' && (
        <div className="bg-surface border border-accent/30 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3 shadow-sm bg-gradient-to-r from-accent/5 via-surface to-transparent">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-accent/10 text-accent">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-body font-semibold text-text-primary">What-If Simulation</span>
                <span className="text-[11px] font-semibold uppercase px-2 py-0.5 rounded bg-accent/20 text-accent border border-accent/30">
                  Side-Effect Free
                </span>
              </div>
              <p className="text-caption text-text-secondary mt-0.5">
                Resolving all <strong className="text-text-primary">{simulation.resolvedFindingCount} open findings</strong> would reduce risk score from{' '}
                <strong className="text-text-primary">{simulation.current.score}</strong> to{' '}
                <strong className="text-emerald-400 font-bold">{simulation.simulated.score}</strong>{' '}
                (Posture {simulation.current.securityPosture}% &rarr;{' '}
                <span className="text-emerald-400 font-bold">{simulation.simulated.securityPosture}%</span>, +{simulation.postureDelta} pts, Grade{' '}
                {simulation.gradeChange.from} &rarr;{' '}
                <span className="text-emerald-400 font-bold">{simulation.gradeChange.to}</span>).
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-caption">
            <span className="px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 font-semibold border border-emerald-500/20">
              +{simulation.postureDelta} Posture Points
            </span>
          </div>
        </div>
      )}

      {/* Findings Table */}
      {loading ? (
        <div className="py-16 flex flex-col items-center justify-center space-y-3">
          <Loader2 className="w-8 h-8 text-accent animate-spin" />
          <p className="text-caption text-text-secondary">Loading findings feed...</p>
        </div>
      ) : filteredFindings.length === 0 ? (
        <div className="bg-surface border border-border rounded-xl p-12 text-center space-y-3">
          <CheckCircle2 className="w-10 h-10 text-sev-low mx-auto" />
          <h3 className="text-body font-semibold text-text-primary">No findings match criteria</h3>
          <p className="text-caption text-text-secondary max-w-sm mx-auto">
            {findings.length === 0
              ? 'No findings recorded under this status view.'
              : 'No findings match your current search or filter settings.'}
          </p>
        </div>
      ) : (
        <div className="bg-surface border border-border rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-body border-collapse">
              <thead>
                <tr className="bg-surface-raised border-b border-border text-caption font-semibold text-text-tertiary uppercase tracking-wider">
                  <th className="py-3.5 px-4">Severity</th>
                  <th className="py-3.5 px-4">Finding & Asset</th>
                  <th className="py-3.5 px-4">Confidence</th>
                  <th className="py-3.5 px-4">Risk Score</th>
                  <th className="py-3.5 px-4">Status</th>
                  <th className="py-3.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filteredFindings.map((finding) => (
                  <tr
                    key={finding.id}
                    onClick={() => handleRowClick(finding)}
                    className="hover:bg-surface-raised/60 transition-colors cursor-pointer"
                  >
                    {/* Severity */}
                    <td className="py-4 px-4 whitespace-nowrap">
                      <SeverityBadge severity={finding.severity} />
                    </td>

                    {/* Title, Category & Asset */}
                    <td className="py-4 px-4">
                      <div className="space-y-1">
                        <div className="font-semibold text-text-primary line-clamp-1">
                          {finding.title}
                        </div>
                        <div className="flex flex-wrap items-center gap-2 text-caption text-text-secondary">
                          <span className="font-mono text-text-primary">{finding.assetFqdn}</span>
                          <span>•</span>
                          <span>{finding.category}</span>
                          {finding.reopenedCount && finding.reopenedCount > 0 ? (
                            <span className="text-sev-critical font-medium bg-sev-critical/10 px-1.5 py-0.2 rounded border border-sev-critical/20 text-[11px]">
                              Re-detected
                            </span>
                          ) : null}
                        </div>
                      </div>
                    </td>

                    {/* Confidence */}
                    <td className="py-4 px-4 whitespace-nowrap">
                      <ConfidenceBadge confidence={finding.confidence} />
                    </td>

                    {/* Risk Score */}
                    <td className="py-4 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <div className="font-bold text-text-primary text-base">
                          {finding.riskScore}{' '}
                          <span className="text-[11px] font-normal text-text-tertiary">/ 100</span>
                        </div>
                        {finding.status === 'OPEN' && finding.riskScore > 0 ? (
                          <span
                            title="Estimated posture improvement if this finding is resolved"
                            className="text-[11px] text-emerald-400 font-medium bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20"
                          >
                            +{Math.max(1, Math.round(finding.riskScore * 0.35))} posture
                          </span>
                        ) : null}
                      </div>
                    </td>

                    {/* Status */}
                    <td className="py-4 px-4 whitespace-nowrap">
                      <StatusBadge status={finding.status} />
                    </td>

                    {/* Action */}
                    <td className="py-4 px-4 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleRowClick(finding);
                        }}
                        className="px-3 py-1 rounded bg-surface-raised hover:bg-surface-overlay text-caption font-semibold text-text-primary border border-border transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination Footer */}
          {totalPages > 1 && (
            <div className="p-4 bg-surface border-t border-border flex items-center justify-between">
              <span className="text-caption text-text-tertiary">
                Showing {findings.length} of {totalCount} findings
              </span>
              <div className="flex items-center gap-2">
                <button
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(p - 1, 1))}
                  className="p-1.5 rounded border border-border bg-surface-raised disabled:opacity-40 text-text-secondary hover:text-text-primary"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <span className="text-caption text-text-secondary font-medium">
                  Page {page} of {totalPages}
                </span>
                <button
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => Math.min(p + 1, totalPages))}
                  className="p-1.5 rounded border border-border bg-surface-raised disabled:opacity-40 text-text-secondary hover:text-text-primary"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Drawer */}
      <EvidenceDrawer
        finding={selectedFinding}
        isOpen={drawerOpen}
        onClose={() => {
          setDrawerOpen(false);
          setSelectedFinding(null);
        }}
        onStatusChange={handleStatusChange}
        userRole={role || 'MEMBER'}
      />
    </div>
  );
}
