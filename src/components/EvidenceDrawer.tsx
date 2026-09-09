'use client';

import React, { useState, useEffect } from 'react';
import {
  X,
  ExternalLink,
  Shield,
  Layers,
  Clock,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Copy,
  Check,
} from 'lucide-react';
import { SeverityBadge } from './SeverityBadge';
import { ConfidenceBadge } from './ConfidenceBadge';
import { StatusBadge } from './StatusBadge';
import { EvidenceBlock } from './EvidenceBlock';
import { AiAnalystCard, AIExplanationData } from './AiAnalystCard';
import { api } from '@/lib/client/api';

export interface FindingDetailItem {
  id: string;
  assetFqdn: string;
  category: string;
  findingCode: string;
  title: string;
  severity: string;
  confidence: string;
  riskScore: number;
  status: 'OPEN' | 'ACCEPTED_RISK' | 'RESOLVED' | 'FALSE_POSITIVE';
  summary: string;
  businessImpact?: string;
  recommendedAction?: string;
  evidence?: {
    checkType?: string;
    observedAt?: string;
    rawSignal?: any;
  };
  lastSeen?: string;
  reopenedCount?: number;
}

interface EvidenceDrawerProps {
  finding: FindingDetailItem | null;
  isOpen: boolean;
  onClose: () => void;
  onStatusChange?: (newStatus: 'OPEN' | 'RESOLVED' | 'ACCEPTED_RISK') => Promise<void>;
  userRole?: string;
}

export function EvidenceDrawer({
  finding,
  isOpen,
  onClose,
  onStatusChange,
  userRole = 'MEMBER',
}: EvidenceDrawerProps) {
  const [aiData, setAiData] = useState<AIExplanationData | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [mutating, setMutating] = useState(false);
  const [copiedRaw, setCopiedRaw] = useState(false);

  const isViewer = userRole === 'VIEWER';

  const fetchAiExplanation = async (findingId: string, force = false) => {
    try {
      setAiLoading(true);
      setAiError(null);
      const url = force
        ? `/api/findings/${findingId}/explain?force=true`
        : `/api/findings/${findingId}/explain`;
      const data = await api.get(url);
      setAiData(data);
    } catch (err: any) {
      setAiError(err.message || 'Failed to retrieve AI analysis');
    } finally {
      setAiLoading(false);
    }
  };

  useEffect(() => {
    if (finding && isOpen) {
      fetchAiExplanation(finding.id);
    } else {
      setAiData(null);
      setAiError(null);
    }
  }, [finding?.id, isOpen]);

  if (!isOpen || !finding) return null;

  const handleStatusUpdate = async (status: 'OPEN' | 'RESOLVED' | 'ACCEPTED_RISK') => {
    if (isViewer || !onStatusChange) return;
    setMutating(true);
    try {
      await onStatusChange(status);
    } finally {
      setMutating(false);
    }
  };

  const handleCopyRaw = () => {
    if (!finding.evidence?.rawSignal) return;
    const str =
      typeof finding.evidence.rawSignal === 'string'
        ? finding.evidence.rawSignal
        : JSON.stringify(finding.evidence.rawSignal, null, 2);
    navigator.clipboard.writeText(str);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden flex justify-end">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity"
        onClick={onClose}
      />

      {/* Drawer Panel */}
      <div className="relative w-full max-w-2xl bg-surface border-l border-border h-full overflow-y-auto shadow-2xl flex flex-col">
        {/* Header */}
        <div className="sticky top-0 bg-surface/95 backdrop-blur border-b border-border p-5 flex items-center justify-between z-10">
          <div className="flex items-center gap-2.5">
            <SeverityBadge severity={finding.severity} />
            <ConfidenceBadge confidence={finding.confidence} />
            <StatusBadge status={finding.status} />
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-text-tertiary hover:text-text-primary rounded-md hover:bg-surface-raised transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6 flex-1">
          {/* Finding Title & Target */}
          <div className="space-y-2">
            <h2 className="text-xl font-bold text-text-primary leading-snug">
              {finding.title}
            </h2>

            <div className="flex flex-wrap items-center gap-4 text-caption text-text-secondary">
              <span className="flex items-center gap-1 font-mono text-text-primary">
                <Layers className="w-3.5 h-3.5 text-text-tertiary" />
                {finding.assetFqdn}
              </span>
              <span>Category: {finding.category}</span>
              {finding.reopenedCount && finding.reopenedCount > 0 ? (
                <span className="text-sev-critical font-medium bg-sev-critical/10 px-2 py-0.5 rounded border border-sev-critical/20">
                  Re-detected {finding.reopenedCount}x
                </span>
              ) : null}
            </div>
          </div>

          {/* Risk Score Pill */}
          <div className="bg-surface-raised border border-border rounded-lg p-3.5 flex items-center justify-between">
            <div>
              <div className="text-caption text-text-tertiary font-medium uppercase tracking-wider">
                Finding Risk Score
              </div>
              <div className="text-2xl font-bold text-text-primary mt-0.5">
                {finding.riskScore} <span className="text-sm font-normal text-text-tertiary">/ 100</span>
              </div>
            </div>
            <div className="text-caption text-text-secondary text-right">
              Formula: Severity × Exposure × Confidence × Importance
            </div>
          </div>

          {/* AI Security Analyst Card */}
          <AiAnalystCard
            data={aiData}
            findingId={finding.id}
            loading={aiLoading}
            error={aiError}
            onRefresh={() => fetchAiExplanation(finding.id, true)}
          />

          {/* Summary */}
          <div className="space-y-2">
            <h3 className="text-caption font-semibold text-text-secondary uppercase tracking-wider">
              Observation Summary
            </h3>
            <p className="text-body text-text-primary leading-relaxed">
              {finding.summary}
            </p>
          </div>

          {/* Raw Evidence Block */}
          {finding.evidence && (
            <div className="space-y-2 pt-2 border-t border-border">
              <div className="flex items-center justify-between">
                <h3 className="text-caption font-semibold text-text-secondary uppercase tracking-wider">
                  Verified Raw Evidence
                </h3>
                <button
                  onClick={handleCopyRaw}
                  className="text-caption text-text-tertiary hover:text-text-primary flex items-center gap-1"
                >
                  {copiedRaw ? <Check className="w-3.5 h-3.5 text-sev-low" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedRaw ? 'Copied' : 'Copy signal'}
                </button>
              </div>

              <EvidenceBlock
                rawSignal={finding.evidence.rawSignal}
                observedAt={finding.evidence.observedAt}
                checkType={finding.evidence.checkType}
              />
            </div>
          )}
        </div>

        {/* Action Footer */}
        <div className="sticky bottom-0 bg-surface/95 backdrop-blur border-t border-border p-4 flex items-center justify-between gap-3">
          {isViewer ? (
            <div className="text-caption text-text-tertiary italic">
              Viewer role has read-only access. Remediation actions are disabled.
            </div>
          ) : (
            <div className="flex items-center gap-2.5 w-full justify-end">
              {finding.status === 'OPEN' ? (
                <>
                  <button
                    disabled={mutating}
                    onClick={() => handleStatusUpdate('ACCEPTED_RISK')}
                    className="px-3.5 py-2 rounded-md border border-border hover:bg-surface-raised text-text-secondary hover:text-text-primary text-body font-medium transition-colors flex items-center gap-1.5 disabled:opacity-50"
                  >
                    <AlertTriangle className="w-4 h-4 text-sev-medium" />
                    Accept Risk
                  </button>

                  <button
                    disabled={mutating}
                    onClick={() => handleStatusUpdate('RESOLVED')}
                    className="px-4 py-2 rounded-md bg-sev-low text-black hover:bg-sev-low/90 text-body font-semibold transition-colors flex items-center gap-1.5 disabled:opacity-50"
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    Mark Resolved
                  </button>
                </>
              ) : (
                <button
                  disabled={mutating}
                  onClick={() => handleStatusUpdate('OPEN')}
                  className="px-3.5 py-2 rounded-md border border-border hover:bg-surface-raised text-text-primary text-body font-medium transition-colors flex items-center gap-1.5 disabled:opacity-50"
                >
                  <RotateCcw className="w-4 h-4 text-accent" />
                  Reopen Finding
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
