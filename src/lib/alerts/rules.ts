import crypto from 'crypto';
import {
  AlertType,
  FindingSeverity,
  FindingConfidence,
  OrgAlertSettings,
  ThreatConfidence,
  ThreatStatus,
} from '@/types';

/**
 * Single tunable constant defining the minimum computed risk score required
 * for a security finding to trigger an alert (§2.1).
 */
export const ALERT_RISK_SCORE_THRESHOLD = 70;

/**
 * Standard suppression window to prevent alert fatigue across recurring scan cycles (§2.3).
 * Defaults to 7 days.
 */
export const ALERT_SUPPRESSION_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

export const DEFAULT_ALERT_SETTINGS: OrgAlertSettings = {
  enabledTypes: [
    'NEW_CRITICAL_FINDING',
    'NEW_HIGH_FINDING',
    'FINDING_AUTO_REOPENED',
    'NEW_ASSET_DISCOVERED',
    'SCAN_FAILED',
    'THREAT_DETECTED',
  ],
  minRiskScore: ALERT_RISK_SCORE_THRESHOLD,
  additionalEmails: [],
  sendToAdmins: true,
};

export interface ShouldAlertFindingResult {
  shouldAlert: boolean;
  alertType?: AlertType;
  reason?: string;
}

/**
 * Pure decision function: Evaluates whether a finding meets the strict alert-generation criteria (§2.1 & §2.2).
 * 
 * Rules:
 * 1. Confidence Guard: Must be CONFIRMED or HIGH (never MEDIUM/LOW/INFORMATIONAL).
 * 2. Severity: Must be CRITICAL or HIGH.
 * 3. Risk-Score Gate: Must meet or exceed minRiskScore (default 70).
 * 4. Organization Preferences: Enabled in org settings.
 */
export function shouldAlertOnFinding(
  finding: {
    severity: FindingSeverity;
    confidence: FindingConfidence;
    riskScore: number;
  },
  asset: {
    importance?: string;
    type?: string;
  },
  orgSettings?: OrgAlertSettings
): ShouldAlertFindingResult {
  const enabled = orgSettings?.enabledTypes || DEFAULT_ALERT_SETTINGS.enabledTypes;

  // 1. Confidence Guard
  if (finding.confidence !== 'CONFIRMED' && finding.confidence !== 'HIGH') {
    return {
      shouldAlert: false,
      reason: `Confidence "${finding.confidence}" below required alert threshold (requires CONFIRMED or HIGH).`,
    };
  }

  // 2. Severity Check
  if (finding.severity !== 'CRITICAL' && finding.severity !== 'HIGH') {
    return {
      shouldAlert: false,
      reason: `Finding severity "${finding.severity}" is not eligible for security alerts (requires CRITICAL or HIGH).`,
    };
  }

  // 3. Computed Risk Score Gate
  const threshold = orgSettings?.minRiskScore ?? ALERT_RISK_SCORE_THRESHOLD;
  if (finding.riskScore < threshold) {
    return {
      shouldAlert: false,
      reason: `Computed risk score (${finding.riskScore}) is below alert threshold (${threshold}).`,
    };
  }

  // 4. Type Enablement Check
  const alertType: AlertType =
    finding.severity === 'CRITICAL' ? 'NEW_CRITICAL_FINDING' : 'NEW_HIGH_FINDING';

  if (!enabled.includes(alertType)) {
    return {
      shouldAlert: false,
      reason: `Alert type "${alertType}" is disabled in organization preferences.`,
    };
  }

  return {
    shouldAlert: true,
    alertType,
  };
}

/**
 * Evaluates whether a newly discovered asset should trigger an alert (§2.1).
 * Fires only for passive discoveries (CT_LOG, DNS_PERMUTATION) and never for MANUAL additions.
 */
export function shouldAlertOnAssetDiscovery(
  method: string,
  orgSettings?: OrgAlertSettings
): { shouldAlert: boolean; reason?: string } {
  const enabled = orgSettings?.enabledTypes || DEFAULT_ALERT_SETTINGS.enabledTypes;

  if (!enabled.includes('NEW_ASSET_DISCOVERED')) {
    return {
      shouldAlert: false,
      reason: 'NEW_ASSET_DISCOVERED is disabled in organization settings.',
    };
  }

  if (method === 'MANUAL') {
    return {
      shouldAlert: false,
      reason: 'Manual asset additions do not trigger passive discovery alerts.',
    };
  }

  return { shouldAlert: true };
}

/**
 * Evaluates whether a detected brand threat should trigger an alert (§6).
 * 
 * Rules:
 * 1. Confidence Guard: Must be CONFIRMED or HIGH (never MEDIUM, LOW, or INFORMATIONAL).
 *    Raw permutation matches and inactive look-alikes are strictly excluded.
 * 2. Corroboration Score Gate: Score must be >= 65.
 * 3. Status Check: Must be in OPEN status.
 * 4. Organization Preferences: THREAT_DETECTED must be enabled.
 */
export function shouldAlertOnThreat(
  threat: {
    confidence: ThreatConfidence;
    corroborationScore: number;
    status: ThreatStatus;
    indicator: string;
  },
  orgSettings?: OrgAlertSettings
): { shouldAlert: boolean; reason?: string } {
  const enabled = orgSettings?.enabledTypes || DEFAULT_ALERT_SETTINGS.enabledTypes;

  if (!enabled.includes('THREAT_DETECTED')) {
    return {
      shouldAlert: false,
      reason: 'THREAT_DETECTED is disabled in organization settings.',
    };
  }

  // 1. Confidence Guard: Only well-corroborated threats alert (never raw matches)
  if (threat.confidence !== 'CONFIRMED' && threat.confidence !== 'HIGH') {
    return {
      shouldAlert: false,
      reason: `Threat confidence "${threat.confidence}" below required alert threshold (requires CONFIRMED or HIGH).`,
    };
  }

  // 2. Corroboration Score Gate
  const threshold = Math.min(65, orgSettings?.minRiskScore ?? 65);
  if (threat.corroborationScore < threshold) {
    return {
      shouldAlert: false,
      reason: `Corroboration score (${threat.corroborationScore}) is below threat alert threshold (${threshold}).`,
    };
  }

  // 3. Status Gate
  if (threat.status !== 'OPEN') {
    return {
      shouldAlert: false,
      reason: `Threat status is "${threat.status}". Only OPEN threats trigger alerts.`,
    };
  }

  return { shouldAlert: true };
}

/**
 * Computes a deterministic deduplication key for an alert (§1 & §2.3).
 */
export function computeAlertDedupKey(
  type: AlertType,
  organizationId: string,
  targetId: string,
  extraQualifier?: string
): string {
  const raw = `${type}:${organizationId}:${targetId}:${extraQualifier || ''}`;
  return crypto.createHash('sha256').update(raw).digest('hex');
}

/**
 * Checks if an alert is suppressed within the suppression window (§2.3).
 * Auto-reopened findings bypass suppression entirely.
 */
export function isAlertSuppressed(
  existingAlerts: Array<{ dedupKey: string; createdAt: Date; type?: string }>,
  dedupKey: string,
  type: AlertType,
  windowMs = ALERT_SUPPRESSION_WINDOW_MS
): boolean {
  // Re-opened findings always bypass suppression window (§2.3)
  if (type === 'FINDING_AUTO_REOPENED') {
    return false;
  }

  const now = Date.now();
  return existingAlerts.some((a) => {
    if (a.dedupKey !== dedupKey) return false;
    const age = now - new Date(a.createdAt).getTime();
    return age < windowMs;
  });
}
