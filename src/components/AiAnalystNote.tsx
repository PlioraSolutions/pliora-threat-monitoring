import React from 'react';

interface AiAnalystNoteProps {
  summary: string;
  impact?: string;
  recommendedAction?: string;
  className?: string;
}

export function AiAnalystNote({
  summary,
  impact,
  recommendedAction,
  className = '',
}: AiAnalystNoteProps) {
  return (
    <div
      className={`bg-surface-raised border border-border border-l-4 border-l-accent rounded-card p-4 space-y-3 ${className}`}
    >
      <div className="text-caption font-medium text-accent">
        AI-generated explanation, grounded in evidence below
      </div>

      <div className="space-y-2 text-body text-text-primary">
        <p className="leading-relaxed">{summary}</p>

        {impact && (
          <div className="pt-2 border-t border-border">
            <span className="font-semibold text-text-secondary">Business impact: </span>
            <span>{impact}</span>
          </div>
        )}

        {recommendedAction && (
          <div className="pt-2 border-t border-border">
            <span className="font-semibold text-text-secondary">Recommended action: </span>
            <span>{recommendedAction}</span>
          </div>
        )}
      </div>
    </div>
  );
}
