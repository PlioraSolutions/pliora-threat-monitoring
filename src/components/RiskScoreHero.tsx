'use client';

import React, { useEffect, useState } from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, AlertCircle } from 'lucide-react';

interface RiskScoreHeroProps {
  score: number;
  letterGrade?: string;
  posture?: string;
  verdict?: string;
  contributingFindingsCount?: number;
}

export function RiskScoreHero({
  score,
  letterGrade,
  posture,
  verdict,
  contributingFindingsCount,
}: RiskScoreHeroProps) {
  const [displayScore, setDisplayScore] = useState(0);

  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (mediaQuery.matches) {
      setDisplayScore(score);
      return;
    }

    const duration = 400;
    const startTime = performance.now();

    const step = (currentTime: number) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplayScore(Math.round(eased * score));

      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        setDisplayScore(score);
      }
    };

    requestAnimationFrame(step);
  }, [score]);

  // Derive Grade if not provided
  const derivedGrade =
    letterGrade ||
    (score >= 80 ? 'F' : score >= 60 ? 'D' : score >= 35 ? 'C' : score >= 15 ? 'B' : 'A');

  // Derive Posture if not provided
  const derivedPosture =
    posture ||
    (score >= 80
      ? 'CRITICAL_RISK'
      : score >= 60
      ? 'NEEDS_ATTENTION'
      : score >= 35
      ? 'MODERATE_EXPOSURE'
      : 'HEALTHY_POSTURE');

  let tierColor = 'text-sev-low';
  let tierBg = 'bg-sev-low/10 border-sev-low/30 text-sev-low';
  let Icon = ShieldCheck;

  if (score >= 80) {
    tierColor = 'text-sev-critical';
    tierBg = 'bg-sev-critical/15 border-sev-critical/30 text-sev-critical';
    Icon = AlertCircle;
  } else if (score >= 60) {
    tierColor = 'text-sev-high';
    tierBg = 'bg-sev-high/15 border-sev-high/30 text-sev-high';
    Icon = AlertTriangle;
  } else if (score >= 35) {
    tierColor = 'text-sev-medium';
    tierBg = 'bg-sev-medium/15 border-sev-medium/30 text-sev-medium';
    Icon = ShieldAlert;
  }

  // Normalized marker position on 0-100 bar
  const markerPercent = Math.min(Math.max(score, 2), 98);

  return (
    <div className="bg-surface border border-border rounded-card p-6 space-y-5 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="text-caption text-text-secondary font-medium uppercase tracking-wider">
            Organization Risk Score
          </div>
          <div className="flex items-baseline gap-3 mt-1">
            <span className={`text-5xl font-bold tracking-tight ${tierColor}`}>
              {displayScore}
            </span>
            <span className="text-text-tertiary text-body">/ 100</span>

            {/* Letter Grade Pill */}
            <span
              className={`ml-2 px-3 py-1 text-sm font-bold rounded-md border flex items-center gap-1.5 ${tierBg}`}
            >
              <Icon className="w-4 h-4" />
              Grade {derivedGrade}
            </span>
          </div>
        </div>

        <div className="text-right">
          <div className="text-caption text-text-tertiary">Security Posture</div>
          <div className="text-body font-semibold text-text-primary capitalize mt-0.5">
            {derivedPosture.replace(/_/g, ' ').toLowerCase()}
          </div>
          {contributingFindingsCount !== undefined && (
            <div className="text-caption text-text-secondary mt-0.5">
              {contributingFindingsCount} active {contributingFindingsCount === 1 ? 'risk factor' : 'risk factors'}
            </div>
          )}
        </div>
      </div>

      {/* Segmented Risk Range Bar with Current Score Marker */}
      <div className="space-y-1.5 pt-2">
        <div className="relative h-2.5 w-full rounded-full bg-surface-overlay overflow-hidden flex gap-0.5">
          <div className="h-full w-[35%] bg-sev-low/70" title="Low risk (0-34)" />
          <div className="h-full w-[25%] bg-sev-medium/70" title="Medium risk (35-59)" />
          <div className="h-full w-[20%] bg-sev-high/70" title="High risk (60-79)" />
          <div className="h-full w-[20%] bg-sev-critical/70" title="Critical risk (80-100)" />
        </div>

        {/* Marker pin */}
        <div className="relative w-full h-1">
          <div
            className="absolute -top-3.5 -ml-1.5 w-3 h-3 rounded-full bg-white border-2 border-surface shadow"
            style={{ left: `${markerPercent}%` }}
            title={`Current score: ${score}`}
          />
        </div>

        <div className="flex justify-between text-caption text-text-tertiary font-mono pt-1">
          <span>0 (Secure)</span>
          <span>35 (Moderate)</span>
          <span>60 (Elevated)</span>
          <span>80 (Critical)</span>
        </div>
      </div>

      {/* Plain Language Verdict */}
      {verdict && (
        <p className="text-body text-text-secondary pt-3 border-t border-border leading-relaxed">
          {verdict}
        </p>
      )}
    </div>
  );
}
