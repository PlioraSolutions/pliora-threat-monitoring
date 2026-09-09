import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { CalibrationFeedback } from '@/models/CalibrationFeedback';
import { FindingCategory, FindingSeverity, FindingConfidence } from '@/types';
import { metrics } from '@/lib/observability/metrics';

export type DriftStatus =
  | 'OPTIMAL_CALIBRATION'
  | 'MISCALIBRATED_OVERCONFIDENT'
  | 'MISCALIBRATED_HIGH_NOISE'
  | 'UNDERVALUED_FINDING'
  | 'INSUFFICIENT_DATA';

export interface FindingGroupDrift {
  groupKey: string;
  findingCode: string;
  category: FindingCategory;
  severityAtTriage: FindingSeverity;
  confidenceAtTriage: FindingConfidence;
  sampleSize: number;
  falsePositiveCount: number;
  falsePositiveRate: number; // 0 to 1
  resolvedCount: number;
  resolvedRate: number; // 0 to 1
  acceptedRiskCount: number;
  acceptedRiskRate: number; // 0 to 1
  reopenedCount: number;
  driftStatus: DriftStatus;
  recommendation?: string;
  suggestedAdjustment?: {
    targetType: 'SEVERITY_WEIGHT' | 'CONFIDENCE_WEIGHT' | 'FINDING_CODE_MULTIPLIER';
    targetKey: string;
    currentValue: number;
    suggestedValue: number;
    rationale: string;
  };
}

export interface CalibrationDriftReport {
  generatedAt: string;
  scope: 'PLATFORM_WIDE' | 'ORGANIZATION';
  organizationId?: string;
  minSampleSize: number;
  totalSamples: number;
  overallFalsePositiveRate: number;
  overallResolutionRate: number;
  overallAcceptedRiskRate: number;
  miscalibratedGroupsCount: number;
  groups: FindingGroupDrift[];
  recommendedAdjustments: Array<{
    findingCode: string;
    targetType: 'SEVERITY_WEIGHT' | 'CONFIDENCE_WEIGHT' | 'FINDING_CODE_MULTIPLIER';
    targetKey: string;
    currentValue: number;
    suggestedValue: number;
    rationale: string;
    driftStatus: DriftStatus;
  }>;
}

export interface DriftAnalysisOptions {
  organizationId?: string;
  minSampleSize?: number; // default: 5
}

/**
 * Retrieves raw feedback records either from MongoDB or memory store.
 */
export async function getCalibrationFeedbackRecords(organizationId?: string): Promise<any[]> {
  if (isMongoActive()) {
    const filter = organizationId ? { organizationId } : {};
    return await CalibrationFeedback.find(filter).lean();
  } else {
    let records = memoryStore.calibrationFeedback;
    if (organizationId) {
      records = records.filter(
        (r) => r.organizationId?.toString() === organizationId.toString()
      );
    }
    return records;
  }
}

/**
 * Computes calibration drift analysis from customer triage actions.
 * Detects overconfidence (>15% FP on Confirmed/High) and high noise (>35% FP on Medium).
 * Enforces statistical significance threshold (default minSampleSize = 5).
 */
export async function analyzeCalibrationDrift(
  options: DriftAnalysisOptions = {}
): Promise<CalibrationDriftReport> {
  const minSampleSize = options.minSampleSize ?? 5;
  const records = await getCalibrationFeedbackRecords(options.organizationId);

  // Group records by findingCode + confidenceAtTriage + severityAtTriage
  const groupsMap = new Map<string, {
    findingCode: string;
    category: FindingCategory;
    severityAtTriage: FindingSeverity;
    confidenceAtTriage: FindingConfidence;
    actions: string[];
  }>();

  for (const r of records) {
    const key = `${r.findingCode}::${r.confidenceAtTriage}::${r.severityAtTriage}`;
    if (!groupsMap.has(key)) {
      groupsMap.set(key, {
        findingCode: r.findingCode,
        category: r.category,
        severityAtTriage: r.severityAtTriage,
        confidenceAtTriage: r.confidenceAtTriage,
        actions: [],
      });
    }
    groupsMap.get(key)!.actions.push(r.action);
  }

  const groups: FindingGroupDrift[] = [];
  const recommendedAdjustments: CalibrationDriftReport['recommendedAdjustments'] = [];

  let totalFp = 0;
  let totalResolved = 0;
  let totalAccepted = 0;
  let miscalibratedCount = 0;

  for (const [groupKey, groupData] of Array.from(groupsMap.entries())) {
    const total = groupData.actions.length;
    const fpCount = groupData.actions.filter((a: string) => a === 'FALSE_POSITIVE').length;
    const resCount = groupData.actions.filter((a: string) => a === 'RESOLVED').length;
    const accCount = groupData.actions.filter((a: string) => a === 'ACCEPTED_RISK').length;
    const reoCount = groupData.actions.filter((a: string) => a === 'REOPENED').length;

    totalFp += fpCount;
    totalResolved += resCount;
    totalAccepted += accCount;

    const fpRate = total > 0 ? Number((fpCount / total).toFixed(4)) : 0;
    const resRate = total > 0 ? Number((resCount / total).toFixed(4)) : 0;
    const accRate = total > 0 ? Number((accCount / total).toFixed(4)) : 0;

    let driftStatus: DriftStatus = 'OPTIMAL_CALIBRATION';
    let recommendation: string | undefined;
    let suggestedAdjustment: FindingGroupDrift['suggestedAdjustment'];

    if (total < minSampleSize) {
      driftStatus = 'INSUFFICIENT_DATA';
      recommendation = `Sample size (${total}/${minSampleSize}) below statistical significance threshold. Additional customer triage feedback required.`;
    } else {
      const isHighConfidence =
        groupData.confidenceAtTriage === 'CONFIRMED' ||
        groupData.confidenceAtTriage === 'HIGH' ||
        groupData.severityAtTriage === 'CRITICAL' ||
        groupData.severityAtTriage === 'HIGH';

      const isMediumConfidence =
        groupData.confidenceAtTriage === 'MEDIUM' || groupData.severityAtTriage === 'MEDIUM';

      const isLowSeverity =
        groupData.severityAtTriage === 'LOW' || groupData.severityAtTriage === 'INFORMATIONAL';

      if (isHighConfidence && fpRate > 0.15) {
        driftStatus = 'MISCALIBRATED_OVERCONFIDENT';
        recommendation = `High false-positive rate (${(fpRate * 100).toFixed(1)}% > 15%) for ${groupData.confidenceAtTriage} confidence tier on ${groupData.findingCode}. Scoring is overconfident. Recommend adjusting confidence weight multiplier down or reducing rule multiplier.`;
        suggestedAdjustment = {
          targetType: 'FINDING_CODE_MULTIPLIER',
          targetKey: groupData.findingCode,
          currentValue: 1.0,
          suggestedValue: 0.75,
          rationale: `Compensate for ${(fpRate * 100).toFixed(1)}% FP rate on ${groupData.findingCode} in production feedback.`,
        };
        miscalibratedCount++;
      } else if (isMediumConfidence && fpRate > 0.35) {
        driftStatus = 'MISCALIBRATED_HIGH_NOISE';
        recommendation = `Excessive false-positive noise (${(fpRate * 100).toFixed(1)}% > 35%) for MEDIUM confidence on ${groupData.findingCode}. Recommend requiring secondary corroboration before alerting.`;
        suggestedAdjustment = {
          targetType: 'FINDING_CODE_MULTIPLIER',
          targetKey: groupData.findingCode,
          currentValue: 1.0,
          suggestedValue: 0.60,
          rationale: `Dampen high false-positive noise (${(fpRate * 100).toFixed(1)}%) until corroboration rule improves.`,
        };
        miscalibratedCount++;
      } else if (isLowSeverity && resRate > 0.85) {
        driftStatus = 'UNDERVALUED_FINDING';
        recommendation = `High customer resolution rate (${(resRate * 100).toFixed(1)}% > 85%) on ${groupData.severityAtTriage} finding ${groupData.findingCode}. Security teams treat this finding as actionable; consider upgrading severity or weight.`;
        suggestedAdjustment = {
          targetType: 'FINDING_CODE_MULTIPLIER',
          targetKey: groupData.findingCode,
          currentValue: 1.0,
          suggestedValue: 1.25,
          rationale: `High resolution velocity (${(resRate * 100).toFixed(1)}%) indicates higher real-world remediation priority than default ${groupData.severityAtTriage}.`,
        };
        miscalibratedCount++;
      } else {
        driftStatus = 'OPTIMAL_CALIBRATION';
        recommendation = `Triage feedback aligns with risk scoring expectations (FP rate ${(fpRate * 100).toFixed(1)}%). Calibration healthy.`;
      }
    }

    const groupResult: FindingGroupDrift = {
      groupKey,
      findingCode: groupData.findingCode,
      category: groupData.category,
      severityAtTriage: groupData.severityAtTriage,
      confidenceAtTriage: groupData.confidenceAtTriage,
      sampleSize: total,
      falsePositiveCount: fpCount,
      falsePositiveRate: fpRate,
      resolvedCount: resCount,
      resolvedRate: resRate,
      acceptedRiskCount: accCount,
      acceptedRiskRate: accRate,
      reopenedCount: reoCount,
      driftStatus,
      recommendation,
      suggestedAdjustment,
    };

    groups.push(groupResult);

    if (suggestedAdjustment && driftStatus !== 'OPTIMAL_CALIBRATION' && driftStatus !== 'INSUFFICIENT_DATA') {
      recommendedAdjustments.push({
        findingCode: groupData.findingCode,
        ...suggestedAdjustment,
        driftStatus,
      });
    }
  }

  const totalSamples = records.length;
  const overallFpRate = totalSamples > 0 ? Number((totalFp / totalSamples).toFixed(4)) : 0;
  const overallResRate = totalSamples > 0 ? Number((totalResolved / totalSamples).toFixed(4)) : 0;
  const overallAccRate = totalSamples > 0 ? Number((totalAccepted / totalSamples).toFixed(4)) : 0;

  // Record into observability telemetry
  metrics.recordCalibrationDrift({
    totalSamples,
    miscalibratedCount,
    platformFpRatePercent: Math.round(overallFpRate * 1000) / 10,
  });

  return {
    generatedAt: new Date().toISOString(),
    scope: options.organizationId ? 'ORGANIZATION' : 'PLATFORM_WIDE',
    organizationId: options.organizationId,
    minSampleSize,
    totalSamples,
    overallFalsePositiveRate: overallFpRate,
    overallResolutionRate: overallResRate,
    overallAcceptedRiskRate: overallAccRate,
    miscalibratedGroupsCount: miscalibratedCount,
    groups,
    recommendedAdjustments,
  };
}
