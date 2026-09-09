'use client';

import React from 'react';
import { TrendingDown, TrendingUp, Minus } from 'lucide-react';

interface HistoryPoint {
  recordedAt: string;
  riskScore: number;
  letterGrade?: string;
  contributingFindingsCount?: number;
}

interface RiskTrendChartProps {
  history: HistoryPoint[];
  className?: string;
}

export function RiskTrendChart({ history, className = '' }: RiskTrendChartProps) {
  if (!history || history.length === 0) {
    return (
      <div className={`bg-surface border border-border rounded-card p-5 flex items-center justify-center text-text-tertiary text-caption min-h-[160px] ${className}`}>
        No historical score snapshots recorded yet. Trend will plot as scans complete.
      </div>
    );
  }

  // Sort chronologically ascending
  const sorted = [...history].sort(
    (a, b) => new Date(a.recordedAt).getTime() - new Date(b.recordedAt).getTime()
  );

  const pointsCount = sorted.length;
  const currentScore = sorted[pointsCount - 1].riskScore;
  const previousScore = pointsCount > 1 ? sorted[pointsCount - 2].riskScore : currentScore;
  const delta = currentScore - previousScore;

  // Chart dimensions
  const width = 500;
  const height = 120;
  const padding = 20;

  const minX = padding;
  const maxX = width - padding;
  const minY = padding;
  const maxY = height - padding;

  // Calculate coordinates
  const coords = sorted.map((pt, idx) => {
    const x = pointsCount === 1 ? width / 2 : minX + (idx / (pointsCount - 1)) * (maxX - minX);
    // Y inverted: 0 score is at bottom (maxY), 100 score is at top (minY)
    const y = maxY - (pt.riskScore / 100) * (maxY - minY);
    return { x, y, ...pt };
  });

  const pathD = coords.reduce((acc, pt, idx) => {
    return idx === 0 ? `M ${pt.x} ${pt.y}` : `${acc} L ${pt.x} ${pt.y}`;
  }, '');

  const areaD =
    coords.length > 1
      ? `${pathD} L ${coords[coords.length - 1].x} ${maxY} L ${coords[0].x} ${maxY} Z`
      : '';

  return (
    <div className={`bg-surface border border-border rounded-card p-5 space-y-3 ${className}`}>
      <div className="flex items-center justify-between">
        <div>
          <div className="text-caption font-medium text-text-secondary uppercase tracking-wider">
            Score History Trend
          </div>
          <div className="text-caption text-text-tertiary">
            {pointsCount} historical {pointsCount === 1 ? 'snapshot' : 'snapshots'}
          </div>
        </div>

        <div className="flex items-center gap-1.5 text-caption font-medium">
          {delta < 0 ? (
            <span className="text-sev-low flex items-center gap-1">
              <TrendingDown className="w-3.5 h-3.5" />
              Improved by {Math.abs(delta)} pts
            </span>
          ) : delta > 0 ? (
            <span className="text-sev-critical flex items-center gap-1">
              <TrendingUp className="w-3.5 h-3.5" />
              Elevated by +{delta} pts
            </span>
          ) : (
            <span className="text-text-tertiary flex items-center gap-1">
              <Minus className="w-3.5 h-3.5" />
              Stable posture
            </span>
          )}
        </div>
      </div>

      <div className="relative w-full overflow-hidden">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="w-full h-28 overflow-visible"
          preserveAspectRatio="none"
        >
          {/* Subtle horizontal grid lines */}
          <line x1={minX} y1={minY} x2={maxX} y2={minY} stroke="var(--border)" strokeDasharray="3 3" />
          <line x1={minX} y1={(minY + maxY) / 2} x2={maxX} y2={(minY + maxY) / 2} stroke="var(--border)" strokeDasharray="3 3" />
          <line x1={minX} y1={maxY} x2={maxX} y2={maxY} stroke="var(--border)" />

          {/* Area fill */}
          {areaD && (
            <path
              d={areaD}
              fill="var(--accent)"
              fillOpacity="0.12"
            />
          )}

          {/* Trend Line */}
          {pathD && (
            <path
              d={pathD}
              fill="none"
              stroke="var(--accent)"
              strokeWidth="2.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          )}

          {/* Data points */}
          {coords.map((pt, idx) => (
            <g key={idx} className="cursor-pointer group">
              <circle
                cx={pt.x}
                cy={pt.y}
                r="4"
                className="fill-surface stroke-accent transition-all group-hover:r-6"
                strokeWidth="2.5"
              />
            </g>
          ))}
        </svg>
      </div>

      <div className="flex justify-between text-[11px] text-text-tertiary font-mono pt-1">
        <span>{new Date(sorted[0].recordedAt).toLocaleDateString()}</span>
        <span>{new Date(sorted[sorted.length - 1].recordedAt).toLocaleDateString()}</span>
      </div>
    </div>
  );
}
