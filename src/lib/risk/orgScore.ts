import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Finding, IFinding } from '@/models/Finding';
import { RiskScoreSnapshot, IRiskScoreSnapshot } from '@/models/RiskScoreSnapshot';
import { FindingSeverity, FindingStatus } from '@/types';

export interface OrgRiskScoreResult {
  score: number; // 0 to 100 (Risk: higher is more exposed)
  securityPosture: number; // 100 - score (Posture: higher is safer)
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  factors: {
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    informationalCount: number;
    totalActiveFindings: number;
    acceptedRiskCount: number;
    topFindingScore: number;
  };
  findingCounts: {
    open: number;
    acceptedRisk: number;
    resolved: number;
    falsePositive: number;
    total: number;
  };
  explanation: string;
}

export const STATUS_WEIGHTS: Record<FindingStatus, number> = {
  OPEN: 1.0,
  ACCEPTED_RISK: 0.3,
  RESOLVED: 0.0,
  FALSE_POSITIVE: 0.0,
};

export function calculateGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
  if (score <= 15) return 'A';
  if (score <= 35) return 'B';
  if (score <= 60) return 'C';
  if (score <= 80) return 'D';
  return 'F';
}

/**
 * Pure calculation function for aggregate risk score across finding records.
 * Uses top-weighted exponential decay to ensure the highest-severity open finding dominates,
 * while preventing single resolved findings from masking high-severity risks.
 */
export function aggregateRiskScore(findings: Array<{
  severity: FindingSeverity;
  status: FindingStatus;
  riskScore: number;
}>): OrgRiskScoreResult {
  let openCount = 0;
  let acceptedRiskCount = 0;
  let resolvedCount = 0;
  let falsePositiveCount = 0;

  const severityCounts: Record<FindingSeverity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFORMATIONAL: 0,
  };

  const activeContributions: number[] = [];

  for (const f of findings) {
    if (f.status === 'OPEN') {
      openCount++;
      if (severityCounts[f.severity] !== undefined) severityCounts[f.severity]++;
    } else if (f.status === 'ACCEPTED_RISK') {
      acceptedRiskCount++;
      if (severityCounts[f.severity] !== undefined) severityCounts[f.severity]++;
    } else if (f.status === 'RESOLVED') {
      resolvedCount++;
    } else if (f.status === 'FALSE_POSITIVE') {
      falsePositiveCount++;
    }

    const weight = STATUS_WEIGHTS[f.status] ?? 0;
    if (weight > 0) {
      const effectiveScore = f.riskScore * weight;
      activeContributions.push(effectiveScore);
    }
  }

  // Sort descending by effective risk contribution
  activeContributions.sort((a, b) => b - a);

  let finalScore = 0;
  let topFindingScore = 0;

  if (activeContributions.length > 0) {
    topFindingScore = activeContributions[0];
    if (activeContributions.length === 1) {
      finalScore = Math.round(topFindingScore);
    } else {
      // Sum of remaining findings with diminishing saturation
      const headroom = 100 - topFindingScore;
      const remainingSum = activeContributions.slice(1).reduce((acc, curr) => acc + curr, 0);
      const additionalRisk = headroom * (1 - Math.exp(-remainingSum / 250));
      finalScore = Math.min(100, Math.round(topFindingScore + additionalRisk));
    }
  }

  const hasSecurityTxtBonus = findings.some(
    (f: any) => f.findingCode === 'TRUST-SECURITY-TXT-PRESENT' && f.status !== 'FALSE_POSITIVE'
  );
  let securityPosture = Math.max(0, 100 - finalScore);
  if (hasSecurityTxtBonus && finalScore > 0) {
    securityPosture = Math.min(100, securityPosture + 5);
  }
  const grade = calculateGrade(100 - securityPosture);

  const explanation =
    activeContributions.length === 0
      ? 'Zero active findings detected. Clean security posture.'
      : `Risk score ${finalScore}/100 anchored by top finding (${topFindingScore.toFixed(0)} pts) with ${activeContributions.length} active findings contributing. Grade: ${grade}.`;

  return {
    score: finalScore,
    securityPosture,
    grade,
    factors: {
      criticalCount: severityCounts.CRITICAL,
      highCount: severityCounts.HIGH,
      mediumCount: severityCounts.MEDIUM,
      lowCount: severityCounts.LOW,
      informationalCount: severityCounts.INFORMATIONAL,
      totalActiveFindings: openCount + acceptedRiskCount,
      acceptedRiskCount,
      topFindingScore: Math.round(topFindingScore),
    },
    findingCounts: {
      open: openCount,
      acceptedRisk: acceptedRiskCount,
      resolved: resolvedCount,
      falsePositive: falsePositiveCount,
      total: findings.length,
    },
    explanation,
  };
}

/**
 * Computes the aggregate risk score for an organization by reading all its findings.
 */
export async function computeOrgRiskScore(organizationId: string): Promise<OrgRiskScoreResult> {
  let orgFindings: any[] = [];

  if (isMongoActive()) {
    orgFindings = await Finding.find({ organizationId });
  } else {
    orgFindings = Array.from(memoryStore.findings.values()).filter(
      (f) => f.organizationId.toString() === organizationId.toString()
    );
  }

  return aggregateRiskScore(orgFindings);
}

/**
 * Persists a point-in-time RiskScoreSnapshot for time-series drift tracking.
 */
export async function recordRiskScoreSnapshot(
  organizationId: string,
  result: OrgRiskScoreResult,
  trigger: 'SCAN_COMPLETED' | 'FINDING_MUTATED' | 'MANUAL' = 'SCAN_COMPLETED',
  scanId?: string
): Promise<any> {
  const snapshotData = {
    organizationId,
    scanId,
    score: result.score,
    securityPosture: result.securityPosture,
    grade: result.grade,
    factors: result.factors,
    trigger,
    computedAt: new Date(),
  };

  if (isMongoActive()) {
    return await RiskScoreSnapshot.create(snapshotData);
  } else {
    const memorySnapshot = {
      _id: `snap-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      ...snapshotData,
      createdAt: new Date(),
    };
    memoryStore.riskScoreSnapshots.push(memorySnapshot);
    return memorySnapshot;
  }
}

export interface WhatIfSimulationResult {
  current: OrgRiskScoreResult;
  simulated: OrgRiskScoreResult;
  scoreDelta: number;
  postureDelta: number;
  gradeChange: {
    from: 'A' | 'B' | 'C' | 'D' | 'F';
    to: 'A' | 'B' | 'C' | 'D' | 'F';
  };
  resolvedFindingCount: number;
  simulatedFindingIds: string[];
}

/**
 * Pure calculation function for what-if risk score simulation (§B.3).
 * Given an organization and finding IDs to hypothetically resolve,
 * calculates the projected score and posture improvements with ZERO side effects.
 * No documents are mutated and no snapshots or audit records are persisted.
 */
export async function simulateRiskScoreIfResolved(
  organizationId: string,
  findingIdsToResolve: string[]
): Promise<WhatIfSimulationResult> {
  let orgFindings: any[] = [];

  if (isMongoActive()) {
    orgFindings = await Finding.find({ organizationId }).lean();
  } else {
    orgFindings = Array.from(memoryStore.findings.values())
      .filter((f) => f.organizationId?.toString() === organizationId.toString())
      .map((f) => ({ ...f }));
  }

  // Calculate current baseline score
  const current = aggregateRiskScore(orgFindings);

  // Normalize IDs set for quick lookup
  const resolveSet = new Set(findingIdsToResolve.map((id) => id.toString()));

  // Pure mapping: clone each finding and hypothetically resolve targeted findings
  let simulatedCount = 0;
  const simulatedFindings = orgFindings.map((f) => {
    const fId = (f._id || f.id || '').toString();
    if (resolveSet.has(fId) && f.status !== 'RESOLVED' && f.status !== 'FALSE_POSITIVE') {
      simulatedCount++;
      return {
        ...f,
        status: 'RESOLVED' as FindingStatus,
      };
    }
    return { ...f };
  });

  // Calculate simulated score purely
  const simulated = aggregateRiskScore(simulatedFindings);

  const scoreDelta = Math.max(0, current.score - simulated.score);
  const postureDelta = Math.max(0, simulated.securityPosture - current.securityPosture);

  return {
    current,
    simulated,
    scoreDelta,
    postureDelta,
    gradeChange: {
      from: current.grade,
      to: simulated.grade,
    },
    resolvedFindingCount: simulatedCount,
    simulatedFindingIds: findingIdsToResolve,
  };
}
