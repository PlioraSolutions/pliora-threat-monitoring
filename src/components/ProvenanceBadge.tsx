import React from 'react';
import { User, FileText, Compass, Network } from 'lucide-react';

interface ProvenanceBadgeProps {
  method: 'MANUAL' | 'CT_LOG' | 'DNS_PERMUTATION' | string;
  className?: string;
}

export function ProvenanceBadge({ method, className = '' }: ProvenanceBadgeProps) {
  const norm = (method || 'MANUAL').toUpperCase();

  let bgClass = 'bg-surface-raised text-text-secondary border-border';
  let label = 'Manual entry';
  let Icon = User;

  if (norm === 'CT_LOG') {
    bgClass = 'bg-accent/10 text-accent border-accent/20';
    label = 'CT Log Discovery';
    Icon = FileText;
  } else if (norm === 'DNS_PERMUTATION') {
    bgClass = 'bg-sev-low/10 text-sev-low border-sev-low/20';
    label = 'DNS Permutation';
    Icon = Network;
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-badge text-caption font-medium border ${bgClass} ${className}`}
      title={`Discovered via: ${label}`}
    >
      <Icon className="w-3 h-3" />
      <span>{label}</span>
    </span>
  );
}
