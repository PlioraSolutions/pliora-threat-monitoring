import React from 'react';

interface EmptyStateProps {
  title: string;
  description: string;
  action?: React.ReactNode;
  className?: string;
}

export function EmptyState({ title, description, action, className = '' }: EmptyStateProps) {
  return (
    <div
      className={`border border-dashed border-border rounded-card p-8 text-left space-y-3 bg-surface ${className}`}
    >
      <div className="text-h2 text-text-primary">{title}</div>
      <p className="text-body text-text-secondary max-w-xl">{description}</p>
      {action && <div className="pt-2">{action}</div>}
    </div>
  );
}
