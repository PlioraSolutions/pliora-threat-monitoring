'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import {
  PlayCircle,
  RefreshCw,
  Loader2,
  CheckCircle2,
  AlertCircle,
  Clock,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  ShieldAlert,
} from 'lucide-react';
import { api } from '@/lib/client/api';
import { StatusBadge } from '@/components/StatusBadge';

interface ScanItem {
  id: string;
  _id?: string;
  targetAssetId: string;
  targetFqdn?: string;
  scanType: string;
  status: 'QUEUED' | 'ACTIVE' | 'COMPLETED' | 'PARTIAL' | 'FAILED';
  progress: number;
  stage?: string;
  diagnostics?: {
    pluginResults?: Array<{
      pluginId: string;
      status: string;
      error?: string;
      durationMs?: number;
    }>;
    wafDetected?: boolean;
    timedOutPlugins?: string[];
  };
  startedAt?: string;
  completedAt?: string;
  createdAt: string;
}

export default function ScansPage() {
  const [scans, setScans] = useState<ScanItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [expandedScanId, setExpandedScanId] = useState<string | null>(null);

  const fetchScans = useCallback(async () => {
    try {
      const res = await api.get('/api/scans');
      const list = res?.data || (Array.isArray(res) ? res : []);
      setScans(list);
    } catch (err) {
      console.error('Failed to load scans:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  // Polling loop when scans are running
  const hasActiveScans = scans.some((s) => s.status === 'ACTIVE' || s.status === 'QUEUED');

  useEffect(() => {
    if (!hasActiveScans) return;

    const interval = setInterval(() => {
      fetchScans();
    }, 3000);

    return () => clearInterval(interval);
  }, [hasActiveScans, fetchScans]);

  const toggleExpand = (id: string) => {
    setExpandedScanId((prev) => (prev === id ? null : id));
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-text-primary">
            Scan History & Pipeline Status
          </h1>
          <p className="text-caption text-text-secondary mt-0.5">
            Audit history of active security sweep pipelines, per-plugin execution diagnostics, and progress tracking.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              setRefreshing(true);
              fetchScans();
            }}
            disabled={refreshing}
            className="px-3.5 py-2 rounded-lg bg-surface border border-border hover:bg-surface-raised text-text-secondary hover:text-text-primary text-caption font-medium transition-colors flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          <Link
            href="/assets"
            className="px-4 py-2 rounded-lg bg-accent hover:bg-accent-hover text-white text-caption font-semibold transition-colors flex items-center gap-1.5 shadow-sm"
          >
            <PlayCircle className="w-4 h-4" />
            <span>Launch Scan from Assets</span>
          </Link>
        </div>
      </div>

      {/* Active Pipeline Status Banner */}
      {hasActiveScans && (
        <div className="bg-accent/10 border border-accent/30 rounded-xl p-4 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Loader2 className="w-5 h-5 text-accent animate-spin" />
            <div>
              <div className="text-body font-semibold text-text-primary">
                Asynchronous Scan Pipeline Active
              </div>
              <div className="text-caption text-text-secondary">
                Auto-polling every 3 seconds until all exposure checks complete.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Scans Table */}
      {loading ? (
        <div className="py-16 flex flex-col items-center justify-center space-y-3">
          <Loader2 className="w-8 h-8 text-accent animate-spin" />
          <p className="text-caption text-text-secondary">Loading scan execution history...</p>
        </div>
      ) : scans.length === 0 ? (
        <div className="bg-surface border border-border rounded-xl p-12 text-center space-y-3">
          <PlayCircle className="w-10 h-10 text-text-tertiary mx-auto" />
          <h3 className="text-body font-semibold text-text-primary">No scans executed yet</h3>
          <p className="text-caption text-text-secondary max-w-sm mx-auto">
            Once you verify your domain, automated sweeps execute to discover exposures and calculate your risk score.
          </p>
          <Link
            href="/assets"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-accent text-white font-medium text-caption shadow mt-2"
          >
            Go to Assets →
          </Link>
        </div>
      ) : (
        <div className="bg-surface border border-border rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-body border-collapse">
              <thead>
                <tr className="bg-surface-raised border-b border-border text-caption font-semibold text-text-tertiary uppercase tracking-wider">
                  <th className="py-3.5 px-4">Target Asset</th>
                  <th className="py-3.5 px-4">Scan Type</th>
                  <th className="py-3.5 px-4">Status</th>
                  <th className="py-3.5 px-4">Progress</th>
                  <th className="py-3.5 px-4">Queued / Completed</th>
                  <th className="py-3.5 px-4 text-right">Diagnostics</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {scans.map((scan) => {
                  const id = scan.id || scan._id!;
                  const isExpanded = expandedScanId === id;
                  const hasDiagnostics =
                    scan.diagnostics?.pluginResults?.length ||
                    scan.diagnostics?.wafDetected ||
                    scan.diagnostics?.timedOutPlugins?.length;

                  return (
                    <React.Fragment key={id}>
                      <tr className="hover:bg-surface-raised/50 transition-colors">
                        {/* Target Asset */}
                        <td className="py-4 px-4 font-mono font-medium text-text-primary">
                          {scan.targetFqdn || scan.targetAssetId}
                        </td>

                        {/* Scan Type */}
                        <td className="py-4 px-4 text-caption text-text-secondary">
                          <span className="bg-surface-raised px-2 py-0.5 rounded border border-border">
                            {scan.scanType.replace(/_/g, ' ')}
                          </span>
                        </td>

                        {/* Status Badge */}
                        <td className="py-4 px-4 whitespace-nowrap">
                          <StatusBadge status={scan.status} />
                        </td>

                        {/* Progress */}
                        <td className="py-4 px-4">
                          <div className="w-32 space-y-1">
                            <div className="flex justify-between text-[11px] font-mono text-text-tertiary">
                              <span>{scan.progress || 0}%</span>
                              {scan.stage && <span>{scan.stage}</span>}
                            </div>
                            <div className="h-1.5 w-full bg-surface-overlay rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full transition-all duration-300 ${
                                  scan.status === 'COMPLETED'
                                    ? 'bg-sev-low'
                                    : scan.status === 'FAILED'
                                    ? 'bg-sev-critical'
                                    : scan.status === 'PARTIAL'
                                    ? 'bg-sev-medium'
                                    : 'bg-accent'
                                }`}
                                style={{ width: `${scan.progress || 5}%` }}
                              />
                            </div>
                          </div>
                        </td>

                        {/* Timestamps */}
                        <td className="py-4 px-4 font-mono text-caption text-text-tertiary whitespace-nowrap">
                          <div>{new Date(scan.createdAt).toLocaleTimeString()}</div>
                          {scan.completedAt && (
                            <div className="text-[11px]">
                              Done: {new Date(scan.completedAt).toLocaleTimeString()}
                            </div>
                          )}
                        </td>

                        {/* Expand / Diagnostic button */}
                        <td className="py-4 px-4 text-right whitespace-nowrap">
                          {hasDiagnostics ? (
                            <button
                              onClick={() => toggleExpand(id)}
                              className="px-2.5 py-1 rounded bg-surface-raised hover:bg-surface-overlay text-caption font-medium text-text-primary border border-border inline-flex items-center gap-1 transition-colors"
                            >
                              <span>Details</span>
                              {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                            </button>
                          ) : (
                            <span className="text-text-tertiary text-caption italic">
                              Standard
                            </span>
                          )}
                        </td>
                      </tr>

                      {/* Expanded Diagnostics Drawer Row */}
                      {isExpanded && hasDiagnostics && (
                        <tr className="bg-surface-raised/80">
                          <td colSpan={6} className="p-4 border-b border-border">
                            <div className="space-y-3 max-w-2xl">
                              <div className="text-caption font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-2">
                                <ShieldAlert className="w-4 h-4 text-accent" />
                                <span>Execution Diagnostics & Plugin Health</span>
                              </div>

                              {/* WAF Detection Notice */}
                              {scan.diagnostics?.wafDetected && (
                                <div className="p-2.5 bg-sev-medium/10 border border-sev-medium/30 rounded text-caption text-sev-medium flex items-center gap-2">
                                  <AlertCircle className="w-4 h-4" />
                                  <span>
                                    WAF / Bot Mitigation detected on target. Results tagged as INCONCLUSIVE where challenge pages were returned.
                                  </span>
                                </div>
                              )}

                              {/* Plugin Results List */}
                              {scan.diagnostics?.pluginResults && (
                                <div className="space-y-1.5">
                                  {scan.diagnostics.pluginResults.map((pr, idx) => (
                                    <div
                                      key={idx}
                                      className="flex items-center justify-between p-2 bg-surface rounded border border-border text-caption font-mono"
                                    >
                                      <span className="font-semibold text-text-primary">
                                        {pr.pluginId}
                                      </span>
                                      <div className="flex items-center gap-3">
                                        {pr.durationMs && (
                                          <span className="text-text-tertiary">{pr.durationMs}ms</span>
                                        )}
                                        <span
                                          className={`px-1.5 py-0.5 rounded text-[11px] font-bold ${
                                            pr.status === 'SUCCESS'
                                              ? 'text-sev-low bg-sev-low/10'
                                              : pr.status === 'TIMED_OUT'
                                              ? 'text-sev-medium bg-sev-medium/10'
                                              : 'text-sev-critical bg-sev-critical/10'
                                          }`}
                                        >
                                          {pr.status}
                                        </span>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
