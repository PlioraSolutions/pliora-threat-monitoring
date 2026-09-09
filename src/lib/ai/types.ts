import { FindingConfidence, ThreatConfidence } from '@/types';

export interface AIExplanationResult {
  explanation: string;
  businessImpact: string;
  remediationSteps: string[];
  confidenceCaveat: string;
  citedEvidenceFields: string[];
  isFallback: boolean;
  isAIGenerated: boolean;
  modelName?: string;
  servedByProvider?: string;
  requestedEvidence?: string;
  generatedAt: string;
  cacheHit?: boolean;
}

export interface ExecutiveSummaryResult {
  executiveSummary: string;
  overallPosture: 'CRITICAL' | 'POOR' | 'MODERATE' | 'GOOD' | 'EXCELLENT';
  keyRisks: Array<{
    title: string;
    severity: string;
    affectedAssetOrIndicator: string;
    impact: string;
  }>;
  priorityActions: string[];
  totalConfirmedFindings: number;
  totalHighThreats: number;
  isFallback: boolean;
  isAIGenerated: boolean;
  generatedAt: string;
}

export interface RemediationGuidance {
  code: string;
  title: string;
  category: string;
  version: string;
  approvedSteps: string[];
}

export interface GroundingValidationResult {
  isValid: boolean;
  violations: string[];
  offendingFields: string[];
}

export type ConfidenceTier = FindingConfidence | ThreatConfidence;
