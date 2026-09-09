import React from 'react';
import { ShieldCheck, ShieldAlert, Shield } from 'lucide-react';

export type ConfidenceLevel =
  | 'CONFIRMED'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFORMATIONAL';

interface ConfidenceBadgeProps {
  confidence: ConfidenceLevel | string;
  showIcon?: boolean;
  className?: string;
}

export function ConfidenceBadge({
  confidence,
  showIcon = true,
  className = '',
}: ConfidenceBadgeProps) {
  const norm = (confidence || 'INFORMATIONAL').toUpperCase();

  let bgClass = 'bg-surface-overlay text-text-secondary border-border';
  let label = 'Informational';
  let Icon = Shield;

  if (norm === 'CONFIRMED') {
    bgClass = 'bg-accent/15 text-accent border-accent/30';
    label = 'Confirmed';
    Icon = ShieldCheck;
  } else if (norm === 'HIGH') {
    bgClass = 'bg-sev-high/15 text-sev-high border-sev-high/30';
    label = 'High Confidence';
    Icon = ShieldCheck;
  } else if (norm === 'MEDIUM') {
    bgClass = 'bg-sev-medium/15 text-sev-medium border-sev-medium/30';
    label = 'Medium Confidence';
    Icon = ShieldAlert;
  } else if (norm === 'LOW') {
    bgClass = 'bg-surface-raised text-text-tertiary border-border';
    label = 'Low Confidence';
    Icon = Shield;
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-badge text-caption font-medium border ${bgClass} ${className}`}
      title={`Confidence tier: ${label}`}
    >
      {showIcon && <Icon className="w-3 h-3" />}
      <span>{label}</span>
    </span>
  );
}
