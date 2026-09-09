import React from 'react';
import {
  CheckCircle2,
  Clock,
  AlertCircle,
  ShieldCheck,
  ShieldAlert,
  Loader2,
  XCircle,
  HelpCircle,
} from 'lucide-react';

interface StatusBadgeProps {
  status: string;
  className?: string;
  size?: 'sm' | 'md';
}

export function StatusBadge({ status, className = '', size = 'sm' }: StatusBadgeProps) {
  const norm = (status || 'UNKNOWN').toUpperCase();

  let bgClass = 'bg-surface-overlay text-text-secondary border-border';
  let label = norm;
  let Icon = HelpCircle;

  switch (norm) {
    // Finding & Threat Lifecycle
    case 'OPEN':
      bgClass = 'bg-sev-critical/10 text-sev-critical border-sev-critical/20';
      label = 'Open';
      Icon = AlertCircle;
      break;
    case 'RESOLVED':
      bgClass = 'bg-sev-low/10 text-sev-low border-sev-low/20';
      label = 'Resolved';
      Icon = CheckCircle2;
      break;
    case 'ACCEPTED_RISK':
      bgClass = 'bg-sev-medium/10 text-sev-medium border-sev-medium/20';
      label = 'Risk Accepted';
      Icon = ShieldAlert;
      break;
    case 'FALSE_POSITIVE':
      bgClass = 'bg-surface-raised text-text-tertiary border-border';
      label = 'False Positive';
      Icon = ShieldCheck;
      break;
    case 'MONITORING':
    case 'ACTIVE_MONITORING':
      bgClass = 'bg-accent/10 text-accent border-accent/20';
      label = 'Monitoring';
      Icon = Clock;
      break;

    // Asset Verification Status
    case 'VERIFIED':
      bgClass = 'bg-sev-low/10 text-sev-low border-sev-low/20';
      label = 'Verified';
      Icon = CheckCircle2;
      break;
    case 'INHERITED_VERIFIED':
      bgClass = 'bg-accent/10 text-accent border-accent/20';
      label = 'Inherited Verification';
      Icon = ShieldCheck;
      break;
    case 'PENDING':
    case 'QUEUED':
      bgClass = 'bg-sev-medium/10 text-sev-medium border-sev-medium/20';
      label = norm === 'QUEUED' ? 'Queued' : 'Verification Pending';
      Icon = Clock;
      break;

    // Scan Status
    case 'ACTIVE':
    case 'IN_PROGRESS':
      bgClass = 'bg-accent/15 text-accent border-accent/30';
      label = 'Scanning';
      Icon = Loader2;
      break;
    case 'COMPLETED':
      bgClass = 'bg-sev-low/10 text-sev-low border-sev-low/20';
      label = 'Completed';
      Icon = CheckCircle2;
      break;
    case 'PARTIAL':
      bgClass = 'bg-sev-medium/15 text-sev-medium border-sev-medium/30';
      label = 'Completed with Diagnostics';
      Icon = AlertCircle;
      break;
    case 'FAILED':
      bgClass = 'bg-sev-critical/10 text-sev-critical border-sev-critical/20';
      label = 'Failed';
      Icon = XCircle;
      break;
  }

  const isSpinning = norm === 'ACTIVE' || norm === 'IN_PROGRESS';

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-badge font-medium border ${
        size === 'sm' ? 'text-caption' : 'text-body'
      } ${bgClass} ${className}`}
    >
      <Icon className={`w-3 h-3 ${isSpinning ? 'animate-spin' : ''}`} />
      <span>{label}</span>
    </span>
  );
}
