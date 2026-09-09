'use client';

import React, { useState } from 'react';
import { Sparkles, CheckCircle2, AlertCircle, RefreshCw, ShieldAlert, Cpu, ThumbsUp, ThumbsDown, Compass } from 'lucide-react';
import { api } from '@/lib/client/api';

export interface AIExplanationData {
  explanation: string;
  businessImpact: string;
  remediationSteps: string[];
  confidenceCaveat: string;
  citedEvidenceFields?: string[];
  requestedEvidence?: string;
  isFallback?: boolean;
  isAIGenerated?: boolean;
  modelName?: string;
  servedByProvider?: string;
  generatedAt?: string;
}

interface AiAnalystCardProps {
  data: AIExplanationData | null;
  findingId?: string;
  loading?: boolean;
  error?: string | null;
  onRefresh?: () => void;
  className?: string;
}

export function AiAnalystCard({
  data,
  findingId,
  loading = false,
  error = null,
  onRefresh,
  className = '',
}: AiAnalystCardProps) {
  const [feedbackRating, setFeedbackRating] = useState<'HELPFUL' | 'UNHELPFUL' | null>(null);
  const [feedbackSubmitting, setFeedbackSubmitting] = useState(false);

  const handleFeedback = async (rating: 'HELPFUL' | 'UNHELPFUL') => {
    if (!findingId || feedbackSubmitting || feedbackRating) return;
    setFeedbackSubmitting(true);
    try {
      await api.post(`/api/findings/${findingId}/explain/feedback`, {
        rating,
        modelName: data?.modelName,
      });
      setFeedbackRating(rating);
    } catch (err) {
      console.error('Failed to submit explanation feedback:', err);
    } finally {
      setFeedbackSubmitting(false);
    }
  };
  if (loading) {
    return (
      <div className={`bg-surface-raised border border-border border-l-4 border-l-accent rounded-card p-5 space-y-3 animate-pulse ${className}`}>
        <div className="flex items-center justify-between">
          <div className="h-4 bg-surface-overlay rounded w-48" />
          <div className="h-4 bg-surface-overlay rounded w-20" />
        </div>
        <div className="h-16 bg-surface-overlay rounded w-full" />
        <div className="h-10 bg-surface-overlay rounded w-3/4" />
      </div>
    );
  }

  if (error) {
    return (
      <div className={`bg-surface-raised border border-sev-critical/30 border-l-4 border-l-sev-critical rounded-card p-5 space-y-2 text-text-secondary ${className}`}>
        <div className="flex items-center gap-2 text-sev-critical font-medium text-body">
          <AlertCircle className="w-4 h-4" />
          <span>Could not generate explanation</span>
        </div>
        <p className="text-caption">{error}</p>
        {onRefresh && (
          <button
            onClick={onRefresh}
            className="text-caption font-medium text-accent hover:underline inline-flex items-center gap-1 mt-1"
          >
            <RefreshCw className="w-3 h-3" /> Retry
          </button>
        )}
      </div>
    );
  }

  if (!data) return null;

  return (
    <div
      className={`bg-surface-raised border border-border border-l-4 border-l-accent rounded-card p-5 space-y-4 shadow-sm ${className}`}
    >
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-accent" />
          <span className="text-body font-semibold text-text-primary">
            AI Security Analyst Explanation
          </span>
        </div>

        <div className="flex items-center gap-2">
          {data.isFallback ? (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-surface-overlay text-text-tertiary border border-border">
              <ShieldAlert className="w-3 h-3" /> Deterministic Policy
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-accent/10 text-accent border border-accent/20">
              <Cpu className="w-3 h-3" /> Grounded ({data.modelName || 'Grounded AI'})
            </span>
          )}

          {onRefresh && (
            <button
              onClick={onRefresh}
              title="Refresh analysis"
              className="p-1 text-text-tertiary hover:text-text-primary transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Main Explanation */}
      <div className="text-body text-text-primary leading-relaxed">
        {data.explanation}
      </div>

      {/* Business Impact Card */}
      {data.businessImpact && (
        <div className="bg-surface/80 border border-border rounded-md p-3 space-y-1">
          <div className="text-caption font-semibold text-text-secondary uppercase tracking-wider">
            Business Impact
          </div>
          <p className="text-body text-text-primary leading-relaxed">
            {data.businessImpact}
          </p>
        </div>
      )}

      {/* Approved Remediation Steps */}
      {data.remediationSteps && data.remediationSteps.length > 0 && (
        <div className="space-y-2 pt-1">
          <div className="text-caption font-semibold text-text-secondary uppercase tracking-wider">
            Approved Remediation Steps
          </div>
          <ul className="space-y-2">
            {data.remediationSteps.map((step, idx) => (
              <li key={idx} className="flex items-start gap-2.5 text-body text-text-primary">
                <CheckCircle2 className="w-4 h-4 text-sev-low shrink-0 mt-0.5" />
                <span className="leading-relaxed">{step}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Bounded Next Investigation Pass */}
      {data.requestedEvidence && (
        <div className="bg-accent/5 border border-accent/20 rounded-md p-3 space-y-1">
          <div className="flex items-center gap-1.5 text-caption font-semibold text-accent uppercase tracking-wider">
            <Compass className="w-3.5 h-3.5" />
            <span>Recommended Next Investigation Pass</span>
          </div>
          <p className="text-body text-text-primary">
            Running an active <code className="font-mono text-xs bg-surface-raised px-1.5 py-0.5 rounded border border-border text-accent">{data.requestedEvidence}</code> pass will verify additional corroboration indicators and increase overall confidence.
          </p>
        </div>
      )}

      {/* Confidence Caveat Notice */}
      {data.confidenceCaveat && (
        <div className="bg-surface-overlay/60 border border-border rounded p-3 text-caption text-text-secondary italic">
          <span className="font-semibold not-italic text-text-tertiary mr-1">Verification Context:</span>
          {data.confidenceCaveat}
        </div>
      )}

      {/* Grounding Cited Fields & Feedback Footer */}
      <div className="pt-2 border-t border-border/60 flex flex-wrap items-center justify-between gap-3 text-[11px] text-text-tertiary">
        {data.citedEvidenceFields && data.citedEvidenceFields.length > 0 ? (
          <div className="flex flex-wrap items-center gap-1.5">
            <span>Grounded in verified fields:</span>
            {data.citedEvidenceFields.map((field) => (
              <span
                key={field}
                className="font-mono bg-mono-bg px-1.5 py-0.5 rounded border border-mono-border text-text-secondary"
              >
                {field}
              </span>
            ))}
          </div>
        ) : <div />}

        {findingId && (
          <div className="flex items-center gap-2">
            <span className="text-text-secondary">Was this explanation helpful?</span>
            {feedbackRating ? (
              <span className="text-emerald-400 font-medium">Thank you for your feedback!</span>
            ) : (
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  disabled={feedbackSubmitting}
                  onClick={() => handleFeedback('HELPFUL')}
                  className="p-1 rounded hover:bg-surface-raised text-text-secondary hover:text-emerald-400 transition-colors"
                  title="Helpful"
                >
                  <ThumbsUp className="w-3.5 h-3.5" />
                </button>
                <button
                  type="button"
                  disabled={feedbackSubmitting}
                  onClick={() => handleFeedback('UNHELPFUL')}
                  className="p-1 rounded hover:bg-surface-raised text-text-secondary hover:text-sev-high transition-colors"
                  title="Unhelpful"
                >
                  <ThumbsDown className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
