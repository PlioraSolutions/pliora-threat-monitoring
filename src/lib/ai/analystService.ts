import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Finding } from '@/models/Finding';
import { Threat } from '@/models/Threat';
import { Evidence } from '@/models/Evidence';
import { Asset } from '@/models/Asset';
import { AuditLog } from '@/models/AuditLog';
import { getLLMProvider } from './provider';
import { RawAIResponseSchema } from './schema';
import { getConfidenceCaveat } from './schema';
import { validateEvidenceGrounding } from './groundingChecker';
import {
  buildFindingExplanationPrompt,
  buildThreatExplanationPrompt,
  buildExecutiveSummaryPrompt,
} from './prompts';
import {
  generateFindingFallback,
  generateThreatFallback,
  generateExecutiveSummaryFallback,
} from './fallback';
import { AIExplanationResult, ExecutiveSummaryResult } from './types';
import { errorTracker } from '@/lib/observability/errorTracker';
import { metrics } from '@/lib/observability/metrics';
import { logger } from '@/lib/observability/logger';

/**
 * Explains a security Finding using Grounded AI analysis, with caching and fallback.
 */
export async function explainFinding(
  findingId: string,
  organizationId: string,
  options: { forceRegenerate?: boolean; actorId?: string; providerOverride?: string } = {}
): Promise<AIExplanationResult | null> {
  const orgIdStr = organizationId.toString();

  // 1. Fetch Finding
  let finding: any = null;
  if (isMongoActive()) {
    finding = await Finding.findOne({ _id: findingId, organizationId });
  } else {
    const candidate = memoryStore.findings.get(findingId);
    if (candidate && candidate.organizationId?.toString() === orgIdStr) {
      finding = candidate;
    } else {
      finding =
        Array.from(memoryStore.findings.values()).find(
          (f) =>
            (f._id?.toString() === findingId || f.id === findingId) &&
            f.organizationId?.toString() === orgIdStr
        ) || null;
    }
  }

  if (!finding) return null;

  // 2. Fetch linked Evidence and Asset
  let evidence: any = null;
  let asset: any = null;

  if (finding.evidenceId) {
    if (isMongoActive()) {
      evidence = await Evidence.findById(finding.evidenceId);
    } else {
      evidence = memoryStore.evidence.get(finding.evidenceId.toString());
    }
  }

  if (finding.assetId) {
    if (isMongoActive()) {
      asset = await Asset.findById(finding.assetId);
    } else {
      asset = memoryStore.assets.get(finding.assetId.toString());
    }
  }

  // 3. Cache check
  const cacheKey = `finding:${findingId}:${finding.status}:${finding.severity}:${finding.riskScore}:${evidence?.contentHash || 'nohash'}`;
  if (!options.forceRegenerate && memoryStore.aiExplanations.has(cacheKey)) {
    const cached = memoryStore.aiExplanations.get(cacheKey);
    return { ...cached, cacheHit: true };
  }

  // 4. Generate explanation via LLM Provider
  const provider = getLLMProvider(options.providerOverride);
  const prompt = buildFindingExplanationPrompt(finding, evidence, asset);

  let explanationResult: AIExplanationResult | null = null;
  let attempts = 0;
  const maxAttempts = 2; // Bounded retry: 1 initial + 1 retry

  while (attempts < maxAttempts && !explanationResult) {
    attempts++;
    try {
      const raw = await provider.generateStructuredCompletion<any>(prompt);
      const parsed = RawAIResponseSchema.safeParse(raw);

      if (!parsed.success) {
        throw new Error(`Schema validation failed: ${parsed.error.message}`);
      }

      // 5. Evidence-Consistency & Grounding Validation
      const grounding = validateEvidenceGrounding(parsed.data, {
        target: finding,
        evidence,
        asset,
      });

      if (!grounding.isValid) {
        // Record grounding failure in audit log
        await recordAuditLog({
          organizationId,
          actorId: options.actorId || 'system',
          action: 'AI_GROUNDING_REJECTED',
          objectType: 'Finding',
          objectId: findingId,
          result: 'FAILURE',
          details: {
            attempt: attempts,
            violations: grounding.violations,
            offendingFields: grounding.offendingFields,
            claimedResponse: parsed.data,
          },
        });

        if (attempts < maxAttempts) {
          // Add stricter instruction for retry
          prompt.userPrompt += `\n\nCRITICAL: Your previous response was REJECTED for grounding violations: ${grounding.violations.join('; ')}. Fix this immediately.`;
          continue;
        } else {
          // Bounded retries exhausted; fall back
          explanationResult = generateFindingFallback(finding, evidence, asset);
          break;
        }
      }

      // Grounding passed! Apply deterministic confidence caveat
      const servedBy = (provider as any).getLastServedProvider?.() || provider.providerName;
      explanationResult = {
        explanation: parsed.data.explanation,
        businessImpact: parsed.data.businessImpact,
        remediationSteps: parsed.data.remediationSteps,
        confidenceCaveat: getConfidenceCaveat(finding.confidence || 'INFORMATIONAL'),
        citedEvidenceFields: parsed.data.citedEvidenceFields,
        requestedEvidence: parsed.data.requestedEvidence,
        isFallback: false,
        isAIGenerated: true,
        modelName: provider.providerName,
        servedByProvider: servedBy,
        generatedAt: new Date().toISOString(),
      };
    } catch (err: any) {
      if (attempts >= maxAttempts) {
        // Fall back on persistent error
        explanationResult = generateFindingFallback(finding, evidence, asset);
      }
    }
  }

  if (!explanationResult) {
    explanationResult = generateFindingFallback(finding, evidence, asset);
  }

  if (explanationResult.isFallback) {
    metrics.recordAIRequest(false, true);
    errorTracker.captureAIFallback(findingId, 'Finding explanation used deterministic fallback', undefined, organizationId);
  } else {
    metrics.recordAIRequest(true, false);
  }

  // 6. Record AuditLog for generation
  await recordAuditLog({
    organizationId,
    actorId: options.actorId || 'system',
    action: 'AI_EXPLANATION_GENERATED',
    objectType: 'Finding',
    objectId: findingId,
    result: 'SUCCESS',
    details: {
      isFallback: explanationResult.isFallback,
      isAIGenerated: explanationResult.isAIGenerated,
      modelName: explanationResult.modelName,
      citedEvidenceFields: explanationResult.citedEvidenceFields,
    },
  });

  // 7. Store in cache
  memoryStore.aiExplanations.set(cacheKey, explanationResult);

  return explanationResult;
}

/**
 * Explains a brand Threat using Grounded AI analysis, with caching and fallback.
 */
export async function explainThreat(
  threatId: string,
  organizationId: string,
  options: { forceRegenerate?: boolean; actorId?: string; providerOverride?: string } = {}
): Promise<AIExplanationResult | null> {
  const orgIdStr = organizationId.toString();

  // 1. Fetch Threat
  let threat: any = null;
  if (isMongoActive()) {
    threat = await Threat.findOne({ _id: threatId, organizationId });
  } else {
    const candidate = memoryStore.threats.get(threatId);
    if (candidate && candidate.organizationId?.toString() === orgIdStr) {
      threat = candidate;
    } else {
      threat =
        Array.from(memoryStore.threats.values()).find(
          (t) =>
            (t._id?.toString() === threatId || t.id === threatId) &&
            t.organizationId?.toString() === orgIdStr
        ) || null;
    }
  }

  if (!threat) return null;

  // 2. Fetch linked Evidence if present
  let evidence: any = null;
  if (threat.evidenceId) {
    if (isMongoActive()) {
      evidence = await Evidence.findById(threat.evidenceId);
    } else {
      evidence = memoryStore.evidence.get(threat.evidenceId.toString());
    }
  }

  // 3. Cache check
  const cacheKey = `threat:${threatId}:${threat.status}:${threat.confidence}:${threat.corroborationScore}`;
  if (!options.forceRegenerate && memoryStore.aiExplanations.has(cacheKey)) {
    const cached = memoryStore.aiExplanations.get(cacheKey);
    return { ...cached, cacheHit: true };
  }

  // 4. Generate explanation via LLM Provider
  const provider = getLLMProvider(options.providerOverride);
  const prompt = buildThreatExplanationPrompt(threat, evidence);

  let explanationResult: AIExplanationResult | null = null;
  let attempts = 0;
  const maxAttempts = 2;

  while (attempts < maxAttempts && !explanationResult) {
    attempts++;
    try {
      const raw = await provider.generateStructuredCompletion<any>(prompt);
      const parsed = RawAIResponseSchema.safeParse(raw);

      if (!parsed.success) {
        throw new Error(`Schema validation failed: ${parsed.error.message}`);
      }

      // Grounding Validation
      const grounding = validateEvidenceGrounding(parsed.data, {
        target: threat,
        evidence,
      });

      if (!grounding.isValid) {
        await recordAuditLog({
          organizationId,
          actorId: options.actorId || 'system',
          action: 'AI_GROUNDING_REJECTED',
          objectType: 'Threat',
          objectId: threatId,
          result: 'FAILURE',
          details: {
            attempt: attempts,
            violations: grounding.violations,
            offendingFields: grounding.offendingFields,
            claimedResponse: parsed.data,
          },
        });

        if (attempts < maxAttempts) {
          prompt.userPrompt += `\n\nCRITICAL: Grounding rejection: ${grounding.violations.join('; ')}. Fix immediately.`;
          continue;
        } else {
          explanationResult = generateThreatFallback(threat, evidence);
          break;
        }
      }

      // Grounding passed
      const servedBy = (provider as any).getLastServedProvider?.() || provider.providerName;
      explanationResult = {
        explanation: parsed.data.explanation,
        businessImpact: parsed.data.businessImpact,
        remediationSteps: parsed.data.remediationSteps,
        confidenceCaveat: getConfidenceCaveat(threat.confidence || 'INFORMATIONAL'),
        citedEvidenceFields: parsed.data.citedEvidenceFields,
        requestedEvidence: parsed.data.requestedEvidence,
        isFallback: false,
        isAIGenerated: true,
        modelName: provider.providerName,
        servedByProvider: servedBy,
        generatedAt: new Date().toISOString(),
      };
    } catch {
      if (attempts >= maxAttempts) {
        explanationResult = generateThreatFallback(threat, evidence);
      }
    }
  }

  if (!explanationResult) {
    explanationResult = generateThreatFallback(threat, evidence);
  }

  if (explanationResult.isFallback) {
    metrics.recordAIRequest(false, true);
    errorTracker.captureAIFallback(threatId, 'Threat explanation used deterministic fallback', undefined, organizationId);
  } else {
    metrics.recordAIRequest(true, false);
  }

  // AuditLog
  await recordAuditLog({
    organizationId,
    actorId: options.actorId || 'system',
    action: 'AI_EXPLANATION_GENERATED',
    objectType: 'Threat',
    objectId: threatId,
    result: 'SUCCESS',
    details: {
      isFallback: explanationResult.isFallback,
      isAIGenerated: explanationResult.isAIGenerated,
      modelName: explanationResult.modelName,
      citedEvidenceFields: explanationResult.citedEvidenceFields,
    },
  });

  // Store in cache
  memoryStore.aiExplanations.set(cacheKey, explanationResult);

  return explanationResult;
}

/**
 * §8 Executive Summary Generator.
 * Aggregates ONLY CONFIRMED/HIGH confidence findings and corroborated threats.
 */
export async function generateExecutiveSummary(
  organizationId: string,
  options: { actorId?: string; providerOverride?: string } = {}
): Promise<ExecutiveSummaryResult> {
  const orgIdStr = organizationId.toString();

  // Load org
  let org: any = null;
  let allFindings: any[] = [];
  let allThreats: any[] = [];

  if (isMongoActive()) {
    const { Organization } = await import('@/models/Organization');
    org = await Organization.findById(organizationId);
    allFindings = await Finding.find({ organizationId });
    allThreats = await Threat.find({ organizationId });
  } else {
    org = memoryStore.organizations.get(orgIdStr) || { name: 'Acme Corporation' };
    allFindings = Array.from(memoryStore.findings.values()).filter(
      (f) => f.organizationId?.toString() === orgIdStr
    );
    allThreats = Array.from(memoryStore.threats.values()).filter(
      (t) => t.organizationId?.toString() === orgIdStr
    );
  }

  // STRICT FILTER: CONFIRMED and HIGH confidence only.
  // MEDIUM, LOW, and INFORMATIONAL items are deliberately excluded to prevent risk overstatement.
  const highQualityFindings = allFindings.filter((f) =>
    ['CONFIRMED', 'HIGH'].includes(f.confidence) && f.status === 'OPEN'
  );
  const highQualityThreats = allThreats.filter((t) =>
    ['CONFIRMED', 'HIGH'].includes(t.confidence) && t.status === 'OPEN'
  );

  const provider = getLLMProvider(options.providerOverride);
  const prompt = buildExecutiveSummaryPrompt(highQualityFindings, highQualityThreats, org);

  try {
    const raw = await provider.generateStructuredCompletion<any>(prompt);
    if (raw && raw.executiveSummary && raw.overallPosture && Array.isArray(raw.keyRisks)) {
      return {
        executiveSummary: raw.executiveSummary,
        overallPosture: raw.overallPosture,
        keyRisks: raw.keyRisks,
        priorityActions: raw.priorityActions || [
          'Review high-priority transport and certificate configurations.',
          'Enforce email security (DMARC) on all brand domains.',
        ],
        totalConfirmedFindings: highQualityFindings.length,
        totalHighThreats: highQualityThreats.length,
        isFallback: false,
        isAIGenerated: true,
        generatedAt: new Date().toISOString(),
      };
    }
  } catch {
    // Fall back gracefully on error
  }

  return generateExecutiveSummaryFallback(highQualityFindings, highQualityThreats, org);
}

/**
 * Internal helper to record audit logs.
 */
async function recordAuditLog(entry: {
  organizationId: any;
  actorId: string;
  action: string;
  objectType: string;
  objectId: string;
  result: 'SUCCESS' | 'FAILURE';
  details?: Record<string, any>;
}) {
  try {
    if (isMongoActive()) {
      await AuditLog.create(entry);
    } else {
      memoryStore.auditLogs.push({
        ...entry,
        createdAt: new Date(),
      });
    }
  } catch {
    // Non-blocking
  }
}
