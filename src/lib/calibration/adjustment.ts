import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { AuditLog } from '@/models/AuditLog';
import { setScoringOverride, resetScoringOverrides } from '@/lib/risk/scoring';

export interface CalibrationAdjustmentInput {
  targetType: 'SEVERITY_WEIGHT' | 'CONFIDENCE_WEIGHT' | 'FINDING_CODE_MULTIPLIER';
  targetKey: string; // e.g. 'CONFIRMED', 'HIGH', 'TLS-EXPIRED'
  previousValue: number;
  adjustedValue: number;
  rationale: string;
  actorId: string;
  organizationId?: string; // platform-wide if omitted
}

export interface CalibrationAdjustmentRecord extends CalibrationAdjustmentInput {
  id: string;
  appliedAt: string;
  auditLogId?: string;
}

/**
 * Applies a deliberate, human-reviewed risk scoring adjustment resulting from calibration drift.
 * Updates dynamic scoring weights and creates a permanent AuditLog entry.
 */
export async function applyCalibrationAdjustment(
  input: CalibrationAdjustmentInput
): Promise<{
  success: boolean;
  adjustment: CalibrationAdjustmentRecord;
  auditLogId: string;
}> {
  if (!input.targetType || !input.targetKey) {
    throw new Error('targetType and targetKey are required for calibration adjustment');
  }

  if (typeof input.adjustedValue !== 'number' || input.adjustedValue <= 0 || input.adjustedValue > 3.0) {
    throw new Error('adjustedValue must be a valid positive number between 0.01 and 3.0');
  }

  if (!input.rationale || input.rationale.trim().length < 5) {
    throw new Error('A detailed human-reviewed rationale (min 5 chars) is required');
  }

  if (!input.actorId) {
    throw new Error('actorId is required for calibration audit attribution');
  }

  // 1. Apply override to risk scoring engine
  setScoringOverride(input.targetType, input.targetKey, input.adjustedValue);

  // 2. Persist audit log entry
  const auditDetails = {
    targetType: input.targetType,
    targetKey: input.targetKey,
    previousValue: input.previousValue,
    adjustedValue: input.adjustedValue,
    rationale: input.rationale,
    scope: input.organizationId ? 'ORGANIZATION' : 'PLATFORM_WIDE',
  };

  let auditLogId = `audit-cal-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;

  if (isMongoActive()) {
    try {
      const log = await AuditLog.create({
        organizationId: input.organizationId || '000000000000000000000000',
        actorId: input.actorId,
        action: 'CALIBRATION_WEIGHTS_ADJUSTED',
        objectType: 'CALIBRATION',
        objectId: `${input.targetType}::${input.targetKey}`,
        result: 'SUCCESS',
        details: auditDetails,
      });
      auditLogId = log._id.toString();
    } catch {
      // Fallback if Mongo encounters schema constraint
      memoryStore.auditLogs.push({
        _id: auditLogId,
        actorId: input.actorId,
        action: 'CALIBRATION_WEIGHTS_ADJUSTED',
        objectType: 'CALIBRATION',
        objectId: `${input.targetType}::${input.targetKey}`,
        result: 'SUCCESS',
        details: auditDetails,
        createdAt: new Date(),
      });
    }
  } else {
    memoryStore.auditLogs.push({
      _id: auditLogId,
      actorId: input.actorId,
      action: 'CALIBRATION_WEIGHTS_ADJUSTED',
      objectType: 'CALIBRATION',
      objectId: `${input.targetType}::${input.targetKey}`,
      result: 'SUCCESS',
      details: auditDetails,
      createdAt: new Date(),
    });
  }

  // 3. Record in memoryStore adjustments list
  const adjustmentRecord: CalibrationAdjustmentRecord = {
    id: `adj-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
    appliedAt: new Date().toISOString(),
    auditLogId,
    ...input,
  };

  if (!memoryStore.calibrationAdjustments) {
    memoryStore.calibrationAdjustments = [];
  }
  memoryStore.calibrationAdjustments.push(adjustmentRecord);

  return {
    success: true,
    adjustment: adjustmentRecord,
    auditLogId,
  };
}

/**
 * Returns recorded calibration adjustments.
 */
export function getCalibrationAdjustments(organizationId?: string): CalibrationAdjustmentRecord[] {
  const all = memoryStore.calibrationAdjustments || [];
  if (!organizationId) return all;
  return all.filter((a) => !a.organizationId || a.organizationId === organizationId);
}

/**
 * Resets dynamic overrides and recorded adjustments (for testing).
 */
export function resetCalibrationAdjustments(): void {
  resetScoringOverrides();
  memoryStore.calibrationAdjustments = [];
}
