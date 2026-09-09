'use client';

import React, { useState, useEffect } from 'react';
import {
  X,
  Shield,
  Mail,
  Server,
  Globe,
  Clock,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
} from 'lucide-react';
import { SeverityBadge } from './SeverityBadge';
import { ConfidenceBadge } from './ConfidenceBadge';
import { StatusBadge } from './StatusBadge';
import { AiAnalystCard, AIExplanationData } from './AiAnalystCard';
import { api } from '@/lib/client/api';

export interface ThreatDetailItem {
  id: string;
  indicator: string;
  similarityScore?: number;
  mutationType?: string;
  severity: string;
  confidence: string;
  corroborationScore: number;
  status: 'OPEN' | 'MONITORING' | 'ACCEPTED_RISK' | 'RESOLVED';
  corroborationFactors?: {
    hasDnsA?: boolean;
    hasMx?: boolean;
    isFreshRegistration?: boolean;
    registrarName?: string;
    asnOrg?: string;
  };
  firstSeen?: string;
  lastSeen?: string;
}

interface ThreatDrawerProps {
  threat: ThreatDetailItem | null;
  isOpen: boolean;
  onClose: () => void;
  onStatusChange?: (newStatus: 'MONITORING' | 'ACCEPTED_RISK' | 'RESOLVED') => Promise<void>;
  userRole?: string;
}

export function ThreatDrawer({
  threat,
  isOpen,
  onClose,
  onStatusChange,
  userRole = 'MEMBER',
}: ThreatDrawerProps) {
  const [aiData, setAiData] = useState<AIExplanationData | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [mutating, setMutating] = useState(false);

  const isViewer = userRole === 'VIEWER';

  const fetchAiExplanation = async (threatId: string, force = false) => {
    try {
      setAiLoading(true);
      setAiError(null);
      const url = force
        ? `/api/threats/${threatId}/explain?force=true`
        : `/api/threats/${threatId}/explain`;
      const data = await api.get(url);
      setAiData(data);
    } catch (err: any) {
      setAiError(err.message || 'Failed to retrieve AI analysis');
    } finally {
      setAiLoading(false);
    }
  };

  useEffect(() => {
    if (threat && isOpen) {
      fetchAiExplanation(threat.id);
    } else {
      setAiData(null);
      setAiError(null);
    }
  }, [threat?.id, isOpen]);

  if (!isOpen || !threat) return null;

  const handleStatusUpdate = async (status: 'MONITORING' | 'ACCEPTED_RISK' | 'RESOLVED') => {
    if (isViewer || !onStatusChange) return;
    setMutating(true);
    try {
      await onStatusChange(status);
    } finally {
      setMutating(false);
    }
  };

  const factors = threat.corroborationFactors || {};

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
            <SeverityBadge severity={threat.severity} />
            <ConfidenceBadge confidence={threat.confidence} />
            <StatusBadge status={threat.status} />
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
          {/* Threat Indicator */}
          <div className="space-y-2">
            <div className="text-caption text-text-secondary uppercase tracking-wider font-semibold">
              Look-Alike Domain Indicator
            </div>
            <h2 className="text-2xl font-mono font-bold text-text-primary">
              {threat.indicator}
            </h2>

            <div className="flex flex-wrap items-center gap-3 text-caption text-text-secondary pt-1">
              {threat.similarityScore !== undefined && (
                <span className="bg-surface-raised px-2 py-0.5 rounded border border-border">
                  Similarity: <strong className="text-text-primary">{threat.similarityScore}%</strong>
                </span>
              )}
              {threat.mutationType && (
                <span className="bg-surface-raised px-2 py-0.5 rounded border border-border">
                  Technique: <strong className="text-text-primary">{threat.mutationType}</strong>
                </span>
              )}
            </div>
          </div>

          {/* Corroboration Score Card */}
          <div className="bg-surface-raised border border-border rounded-lg p-4 space-y-3">
            <div className="flex items-baseline justify-between">
              <div>
                <div className="text-caption text-text-tertiary font-medium uppercase tracking-wider">
                  Corroboration Score
                </div>
                <div className="text-2xl font-bold text-text-primary mt-0.5">
                  {threat.corroborationScore} <span className="text-sm font-normal text-text-tertiary">/ 100</span>
                </div>
              </div>

              <div className="text-caption text-text-secondary text-right">
                {threat.corroborationScore >= 65 ? (
                  <span className="text-sev-critical font-semibold">High Threat Signal</span>
                ) : (
                  <span className="text-text-tertiary">Low Corroboration</span>
                )}
              </div>
            </div>

            {/* Corroboration factors breakdown */}
            <div className="grid grid-cols-2 gap-2.5 pt-2 border-t border-border">
              <div className="flex items-center gap-2 text-caption">
                <Globe className={`w-4 h-4 ${factors.hasDnsA ? 'text-sev-high' : 'text-text-tertiary'}`} />
                <span>
                  DNS Resolution: <strong>{factors.hasDnsA ? 'Active IP' : 'No DNS'}</strong>
                </span>
              </div>

              <div className="flex items-center gap-2 text-caption">
                <Mail className={`w-4 h-4 ${factors.hasMx ? 'text-sev-critical' : 'text-text-tertiary'}`} />
                <span>
                  Mail Server: <strong>{factors.hasMx ? 'MX Active' : 'None'}</strong>
                </span>
              </div>

              <div className="flex items-center gap-2 text-caption">
                <Clock className={`w-4 h-4 ${factors.isFreshRegistration ? 'text-sev-high' : 'text-text-tertiary'}`} />
                <span>
                  Registration: <strong>{factors.isFreshRegistration ? 'Recently Created' : 'Older / Unknown'}</strong>
                </span>
              </div>

              <div className="flex items-center gap-2 text-caption">
                <Server className="w-4 h-4 text-text-tertiary" />
                <span className="truncate" title={factors.asnOrg || 'Unknown ASN'}>
                  ASN: <strong>{factors.asnOrg || 'Unknown'}</strong>
                </span>
              </div>
            </div>
          </div>

          {/* AI Threat Explanation */}
          <AiAnalystCard
            data={aiData}
            loading={aiLoading}
            error={aiError}
            onRefresh={() => fetchAiExplanation(threat.id, true)}
          />
        </div>

        {/* Action Footer */}
        <div className="sticky bottom-0 bg-surface/95 backdrop-blur border-t border-border p-4 flex items-center justify-end gap-3">
          {isViewer ? (
            <div className="text-caption text-text-tertiary italic">
              Viewer role has read-only access.
            </div>
          ) : (
            <div className="flex items-center gap-2.5">
              {threat.status !== 'MONITORING' && (
                <button
                  disabled={mutating}
                  onClick={() => handleStatusUpdate('MONITORING')}
                  className="px-3.5 py-2 rounded-md border border-border hover:bg-surface-raised text-text-secondary hover:text-text-primary text-body font-medium transition-colors disabled:opacity-50"
                >
                  Monitor Domain
                </button>
              )}

              {threat.status !== 'ACCEPTED_RISK' && (
                <button
                  disabled={mutating}
                  onClick={() => handleStatusUpdate('ACCEPTED_RISK')}
                  className="px-3.5 py-2 rounded-md border border-border hover:bg-surface-raised text-text-secondary hover:text-text-primary text-body font-medium transition-colors flex items-center gap-1.5 disabled:opacity-50"
                >
                  <AlertTriangle className="w-4 h-4 text-sev-medium" />
                  Accept Risk
                </button>
              )}

              {threat.status !== 'RESOLVED' && (
                <button
                  disabled={mutating}
                  onClick={() => handleStatusUpdate('RESOLVED')}
                  className="px-4 py-2 rounded-md bg-sev-low text-black hover:bg-sev-low/90 text-body font-semibold transition-colors flex items-center gap-1.5 disabled:opacity-50"
                >
                  <CheckCircle2 className="w-4 h-4" />
                  Mark Resolved
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
