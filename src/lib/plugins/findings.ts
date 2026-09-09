import crypto from 'crypto';
import { FindingSpec, CheckPlugin, PluginEvidenceSpec } from './types';

/**
 * Computes a deterministic SHA-256 deduplication hash for a finding.
 * Guarantees a unique constraint on (organizationId, dedupHash) to prevent repeat scan spam.
 */
export function computeFindingDedupHash(
  organizationId: string,
  assetId: string,
  findingCode: string
): string {
  return crypto
    .createHash('sha256')
    .update(`${organizationId}:${assetId}:${findingCode}`)
    .digest('hex');
}

/**
 * Validates and maps raw plugin findings into normalized Finding records.
 * Enforces the non-negotiable hard guard on fingerprint-derived finding severities.
 */
export function validateAndMapFinding(
  spec: FindingSpec,
  plugin: CheckPlugin,
  asset: { fqdn: string; _id?: any; organizationId?: any }
): FindingSpec {
  // Hard Guard (§2.1 & §5):
  // The finding-creation function must reject any attempt to create a HIGH or CRITICAL
  // severity Finding from fingerprint evidence without an independent corroborating check.
  const isFingerprintCheck =
    plugin.category === 'TECH_VERSION' || spec.category === 'TECH_VERSION';

  if (isFingerprintCheck && (spec.severity === 'HIGH' || spec.severity === 'CRITICAL')) {
    if (!spec.hasCorroboratingEvidence) {
      throw new Error(
        `CRITICAL GUARD VIOLATION: Plugin "${plugin.id}" attempted to create ${spec.severity} finding "${spec.findingCode}" from uncorroborated fingerprint evidence. Tech version findings must not exceed MEDIUM severity without verifiable behavioral exploitation evidence.`
      );
    }
  }

  // Enforce plugin defaultConfidence as ceiling unless explicitly lower
  const confidenceOrder = ['INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CONFIRMED'];
  const pluginCeilingIndex = confidenceOrder.indexOf(plugin.defaultConfidence);
  const requestedConfidenceIndex = confidenceOrder.indexOf(spec.confidence);

  let finalConfidence = spec.confidence;
  if (requestedConfidenceIndex > pluginCeilingIndex && !spec.hasCorroboratingEvidence) {
    finalConfidence = plugin.defaultConfidence;
  }

  return {
    ...spec,
    confidence: finalConfidence,
  };
}

/**
 * Maps raw evidence observations and plugin finding specs into validated finding objects.
 */
export function evidenceToFindings(
  evidence: PluginEvidenceSpec,
  findings: FindingSpec[],
  plugin: CheckPlugin,
  asset: { fqdn: string; _id?: any; organizationId?: any }
): FindingSpec[] {
  return findings.map((f) => validateAndMapFinding(f, plugin, asset));
}
