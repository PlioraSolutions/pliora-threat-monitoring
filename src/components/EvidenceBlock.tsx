import React from 'react';

interface EvidenceBlockProps {
  rawSignal: string | Record<string, any>;
  observedAt?: string | Date;
  checkType?: string;
  className?: string;
}

export function EvidenceBlock({
  rawSignal,
  observedAt,
  checkType,
  className = '',
}: EvidenceBlockProps) {
  const formattedTime = observedAt
    ? new Date(observedAt).toISOString().replace('T', ' ').substring(0, 19) + ' UTC'
    : 'Recent scan observation';

  const contentString =
    typeof rawSignal === 'string'
      ? rawSignal
      : JSON.stringify(rawSignal, null, 2);

  return (
    <div className={`space-y-1.5 ${className}`}>
      <div className="flex items-center justify-between text-caption text-text-tertiary">
        <span className="font-medium text-text-secondary">
          Evidence{checkType ? ` (${checkType})` : ''}
        </span>
        <span className="font-mono text-text-tertiary">{formattedTime}</span>
      </div>

      <div className="bg-mono-bg border border-mono-border rounded-evidence p-3 overflow-x-auto">
        <pre className="font-mono text-mono text-text-primary whitespace-pre-wrap break-all leading-relaxed">
          {contentString}
        </pre>
      </div>
    </div>
  );
}
