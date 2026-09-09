'use client';

import React, { useState, useEffect } from 'react';
import { X, FileText, CheckCircle2, AlertTriangle, ShieldCheck, Download, RefreshCw } from 'lucide-react';
import { api } from '@/lib/client/api';

interface ExecutiveSummaryData {
  executiveSummary: string;
  overallPosture: string;
  keyRisks: (string | Record<string, string>)[];
  priorityActions: (string | Record<string, string>)[];
  totalConfirmedFindings: number;
  totalHighThreats: number;
  generatedAt: string;
}

/** Coerce any item (string or object) to a displayable string. */
function toText(item: string | Record<string, string>): string {
  if (typeof item === 'string') return item;
  // object: {title, severity, affectedAssetOrIndicator, impact}
  return [item.title, item.impact, item.affectedAssetOrIndicator]
    .filter(Boolean)
    .join(' — ');
}

interface ExecutiveSummaryModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function ExecutiveSummaryModal({ isOpen, onClose }: ExecutiveSummaryModalProps) {
  const [data, setData] = useState<ExecutiveSummaryData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchSummary = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.get('/api/reports/executive-summary');
      setData(res);
    } catch (err: any) {
      setError(err.message || 'Failed to generate executive summary');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchSummary();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto flex items-center justify-center p-4">
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />

      {/* Modal Card */}
      <div className="relative w-full max-w-2xl bg-surface border border-border rounded-xl shadow-2xl p-6 space-y-6 z-10 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-border">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-accent/10 rounded-lg text-accent">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-text-primary">Executive Security Summary</h2>
              <div className="text-caption text-text-tertiary">
                High-level business risk overview based on confirmed findings
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={fetchSummary}
              disabled={loading}
              title="Refresh summary"
              className="p-1.5 text-text-tertiary hover:text-text-primary rounded-md transition-colors"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-text-tertiary hover:text-text-primary rounded-md transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {loading ? (
          <div className="space-y-4 py-8 animate-pulse">
            <div className="h-6 bg-surface-overlay rounded w-1/3" />
            <div className="h-24 bg-surface-overlay rounded w-full" />
            <div className="h-32 bg-surface-overlay rounded w-full" />
          </div>
        ) : error ? (
          <div className="p-5 bg-sev-critical/10 border border-sev-critical/30 rounded-lg text-text-secondary space-y-2">
            <div className="font-semibold text-sev-critical flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" /> Could not load executive summary
            </div>
            <p className="text-caption">{error}</p>
          </div>
        ) : data ? (
          <div className="space-y-6">
            {/* Posture & Stat Badges */}
            <div className="flex flex-wrap items-center gap-3">
              <div className="bg-surface-raised border border-border px-3 py-1.5 rounded-lg flex items-center gap-2 text-caption">
                <ShieldCheck className="w-4 h-4 text-accent" />
                <span>
                  Posture: <strong className="text-text-primary capitalize">{data.overallPosture.replace(/_/g, ' ').toLowerCase()}</strong>
                </span>
              </div>

              <div className="bg-surface-raised border border-border px-3 py-1.5 rounded-lg flex items-center gap-2 text-caption">
                <span>Confirmed Findings: <strong className="text-text-primary">{data.totalConfirmedFindings}</strong></span>
              </div>

              <div className="bg-surface-raised border border-border px-3 py-1.5 rounded-lg flex items-center gap-2 text-caption">
                <span>High Threats: <strong className="text-text-primary">{data.totalHighThreats}</strong></span>
              </div>
            </div>

            {/* Narrative Summary */}
            <div className="space-y-2">
              <h3 className="text-caption font-semibold text-text-secondary uppercase tracking-wider">
                Leadership Summary
              </h3>
              <p className="text-body text-text-primary leading-relaxed bg-surface-raised border border-border rounded-lg p-4">
                {data.executiveSummary}
              </p>
            </div>

            {/* Key Risks */}
            {data.keyRisks && data.keyRisks.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-caption font-semibold text-text-secondary uppercase tracking-wider">
                  Key Exposure Areas
                </h3>
                <ul className="space-y-2">
                  {data.keyRisks.map((risk, idx) => (
                    <li key={idx} className="flex items-start gap-2.5 text-body text-text-primary">
                      <AlertTriangle className="w-4 h-4 text-sev-high shrink-0 mt-0.5" />
                      <span className="leading-relaxed">{toText(risk)}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Priority Actions */}
            {data.priorityActions && data.priorityActions.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-caption font-semibold text-text-secondary uppercase tracking-wider">
                  Priority Action Checklist
                </h3>
                <ul className="space-y-2">
                  {data.priorityActions.map((action, idx) => (
                    <li key={idx} className="flex items-start gap-2.5 text-body text-text-primary">
                      <CheckCircle2 className="w-4 h-4 text-sev-low shrink-0 mt-0.5" />
                      <span className="leading-relaxed">{toText(action)}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="pt-2 text-caption text-text-tertiary">
              Generated: {new Date(data.generatedAt).toLocaleString()} • Grounded strictly on confirmed security evidence.
            </div>
          </div>
        ) : null}

        {/* Footer */}
        <div className="pt-4 border-t border-border flex items-center justify-between">
          <a
            href="/api/reports/export"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-2 rounded-md bg-accent text-white hover:bg-accent/90 text-caption font-semibold transition-colors"
          >
            <Download className="w-4 h-4" />
            Export / Print PDF
          </a>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-md bg-surface-raised hover:bg-surface-overlay border border-border text-body font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
