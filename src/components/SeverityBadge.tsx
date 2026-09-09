import React from 'react';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL' | 'INFO';

interface SeverityBadgeProps {
  severity: SeverityLevel | string;
  className?: string;
}

export function SeverityBadge({ severity, className = '' }: SeverityBadgeProps) {
  const norm = (severity || 'INFO').toUpperCase();

  let bgClass = 'bg-sev-info-bg text-sev-info';
  let label = 'Informational';

  if (norm === 'CRITICAL') {
    bgClass = 'bg-sev-critical-bg text-sev-critical';
    label = 'Critical';
  } else if (norm === 'HIGH') {
    bgClass = 'bg-sev-high-bg text-sev-high';
    label = 'High';
  } else if (norm === 'MEDIUM') {
    bgClass = 'bg-sev-medium-bg text-sev-medium';
    label = 'Medium';
  } else if (norm === 'LOW') {
    bgClass = 'bg-sev-low-bg text-sev-low';
    label = 'Low';
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-badge text-caption font-medium ${bgClass} ${className}`}
    >
      <span className="text-[10px] leading-none">●</span>
      <span>{label}</span>
    </span>
  );
}
