import { FindingSeverity, FindingConfidence, AssetImportance } from '@/types';
import { deriveExposure, AssetExposureInput } from './exposure';

/**
 * ============================================================================
 * PLIŌRA RISK SCORING WEIGHTS & CALIBRATION CHANGELOG
 * ============================================================================
 * 
 * Changelog:
 * - 2026-03-01 [Baseline]: Initial foundational weights configured for
 *   Severity (Critical: 1.0 down to Info: 0.05), Confidence (Confirmed: 1.0 down to Info: 0.2),
 *   and Asset Importance.
 * - 2026-09-06 [Phase B Moat §B.4]: Introduced dynamic human-in-the-loop calibration
 *   weight adjustments. Allows overriding confidence, severity, and rule-specific
 *   findingCode multipliers based on statistical drift analysis from triage data
 *   (FALSE_POSITIVE, RESOLVED, ACCEPTED_RISK).
 * ============================================================================
 */

export interface FindingRiskInput {
  severity: FindingSeverity;
  confidence: FindingConfidence;
  category?: string;
  findingCode?: string;
}

export interface AssetRiskInput extends AssetExposureInput {
  importance?: AssetImportance;
}

export interface RiskScoreResult {
  score: number; // 0 to 100
  factors: {
    severity: number;
    exposure: number;
    confidence: number;
    assetImportance: number;
    findingMultiplier?: number;
    rawRisk: number;
  };
  explanation: string;
}

export const BASELINE_SEVERITY_WEIGHTS: Record<FindingSeverity, number> = {
  CRITICAL: 1.0,
  HIGH: 0.75,
  MEDIUM: 0.5,
  LOW: 0.25,
  INFORMATIONAL: 0.05,
};

export const BASELINE_CONFIDENCE_WEIGHTS: Record<FindingConfidence, number> = {
  CONFIRMED: 1.0,
  HIGH: 0.85,
  MEDIUM: 0.65,
  LOW: 0.4,
  INFORMATIONAL: 0.2,
};

export const IMPORTANCE_WEIGHTS: Record<AssetImportance, number> = {
  CRITICAL: 1.0,
  HIGH: 0.8,
  NORMAL: 0.6,
  LOW: 0.4,
};

// Aliases for baseline weights
export const SEVERITY_WEIGHTS = BASELINE_SEVERITY_WEIGHTS;
export const CONFIDENCE_WEIGHTS = BASELINE_CONFIDENCE_WEIGHTS;

// Dynamic overrides applied via reviewed calibration adjustments
const dynamicSeverityOverrides = new Map<string, number>();
const dynamicConfidenceOverrides = new Map<string, number>();
const dynamicFindingMultipliers = new Map<string, number>();

export function getSeverityWeight(severity: FindingSeverity): number {
  return dynamicSeverityOverrides.get(severity) ?? BASELINE_SEVERITY_WEIGHTS[severity] ?? 0.5;
}

export function getConfidenceWeight(confidence: FindingConfidence): number {
  return dynamicConfidenceOverrides.get(confidence) ?? BASELINE_CONFIDENCE_WEIGHTS[confidence] ?? 0.65;
}

export function getFindingMultiplier(findingCode?: string): number {
  if (!findingCode) return 1.0;
  return dynamicFindingMultipliers.get(findingCode) ?? 1.0;
}

export function setScoringOverride(
  targetType: 'SEVERITY_WEIGHT' | 'CONFIDENCE_WEIGHT' | 'FINDING_CODE_MULTIPLIER',
  targetKey: string,
  value: number
): void {
  if (targetType === 'SEVERITY_WEIGHT') {
    dynamicSeverityOverrides.set(targetKey, value);
  } else if (targetType === 'CONFIDENCE_WEIGHT') {
    dynamicConfidenceOverrides.set(targetKey, value);
  } else if (targetType === 'FINDING_CODE_MULTIPLIER') {
    dynamicFindingMultipliers.set(targetKey, value);
  }
}

export function resetScoringOverrides(): void {
  dynamicSeverityOverrides.clear();
  dynamicConfidenceOverrides.clear();
  dynamicFindingMultipliers.clear();
}

/**
 * Computes a normalized risk score (0 to 100) for a finding on an asset.
 * 
 * Formula:
 *   RawRisk = SeverityWeight × ExposureFactor × ConfidenceWeight × AssetImportanceWeight × FindingMultiplier
 *   Score   = round(RawRisk × 100)
 * 
 * Pure function: Deterministic, no side effects, no database calls.
 */
export function computeRiskScore(
  finding: FindingRiskInput,
  asset: AssetRiskInput
): RiskScoreResult {
  const severityWeight = getSeverityWeight(finding.severity);
  const confidenceWeight = getConfidenceWeight(finding.confidence);
  const importanceWeight = IMPORTANCE_WEIGHTS[asset.importance || 'NORMAL'] ?? 0.6;
  const findingMultiplier = getFindingMultiplier(finding.findingCode);

  const exposureBreakdown = deriveExposure(asset);
  const exposureFactor = exposureBreakdown.exposureFactor;

  const rawRisk = severityWeight * exposureFactor * confidenceWeight * importanceWeight * findingMultiplier;
  const score = Math.min(100, Math.max(0, Math.round(rawRisk * 100)));

  const multiplierText = findingMultiplier !== 1.0 ? `, Finding Multiplier (${findingMultiplier.toFixed(2)}x)` : '';
  const explanation =
    `Score ${score}/100 computed from Severity (${finding.severity}: ${(severityWeight * 100).toFixed(0)}%), ` +
    `Exposure (${(exposureFactor * 100).toFixed(0)}% for ${asset.type || 'DOMAIN'}), ` +
    `Confidence (${finding.confidence}: ${(confidenceWeight * 100).toFixed(0)}%), ` +
    `Asset Importance (${asset.importance || 'NORMAL'}: ${(importanceWeight * 100).toFixed(0)}%)` +
    `${multiplierText}.`;

  return {
    score,
    factors: {
      severity: severityWeight,
      exposure: exposureFactor,
      confidence: confidenceWeight,
      assetImportance: importanceWeight,
      findingMultiplier,
      rawRisk: Number(rawRisk.toFixed(4)),
    },
    explanation,
  };
}
