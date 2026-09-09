import crypto from 'crypto';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Threat, IThreat } from '@/models/Threat';
import { Evidence } from '@/models/Evidence';
import { AuditLog } from '@/models/AuditLog';
import { generateDomainPermutations } from './permutations';
import { queryCertificateTransparency } from '@/lib/discovery/ctLog';
import { resolveDomainDns, lookupDomainAge, lookupIpAsn } from './intel';
import { computeCorroborationScore } from './corroboration';
import { triggerAlert } from '@/lib/alerts/service';
import { ThreatSource } from '@/types';

export interface ThreatMonitoringOptions {
  organizationId: string;
  rootDomain: string;
  brandKeyword?: string;
  maxDnsChecks?: number;
}

export interface ThreatMonitoringResult {
  rootDomain: string;
  totalPermutationsGenerated: number;
  candidatesEvaluated: number;
  threatsCreated: number;
  threatsUpdated: number;
  alertsTriggered: number;
  threats: any[];
}

/**
 * Computes deterministic deduplication key for a threat indicator.
 */
export function computeThreatDedupKey(organizationId: string, indicator: string): string {
  const raw = `${organizationId.toString()}:${indicator.toLowerCase().trim()}`;
  return crypto.createHash('sha256').update(raw).digest('hex');
}

/**
 * Canonical upsert for Threat records across MongoDB and in-memory store.
 * Preserves earliest firstSeen, refreshes lastSeen, updates corroboration factors,
 * and handles lifecycle state preservation.
 */
export async function upsertThreatRecord(params: {
  organizationId: string;
  indicator: string;
  relatedRootDomain: string;
  source: ThreatSource;
  confidence: any;
  corroborationScore: number;
  corroborationFactors?: any;
  evidenceId?: any;
  resolvedIps?: string[];
  registrarAge?: number;
  hostingAsn?: string;
  hostingOrg?: string;
}): Promise<{ threat: any; isNew: boolean }> {
  const dedupKey = computeThreatDedupKey(params.organizationId, params.indicator);
  const now = new Date();

  if (isMongoActive()) {
    let existing = await Threat.findOne({
      organizationId: params.organizationId,
      dedupKey,
    });

    if (existing) {
      existing.lastSeen = now;
      existing.corroborationScore = params.corroborationScore;
      existing.confidence = params.confidence;
      existing.corroborationFactors = params.corroborationFactors;
      if (params.evidenceId) existing.evidenceId = params.evidenceId;
      if (params.resolvedIps) existing.resolvedIps = params.resolvedIps;
      if (params.registrarAge !== undefined) existing.registrarAge = params.registrarAge;
      if (params.hostingAsn) existing.hostingAsn = params.hostingAsn;
      if (params.hostingOrg) existing.hostingOrg = params.hostingOrg;

      // Auto-reopen if domain previously marked RESOLVED is re-detected as live
      if (existing.status === 'RESOLVED' && params.corroborationScore >= 45) {
        existing.status = 'OPEN';
      }

      await existing.save();
      return { threat: existing, isNew: false };
    }

    const newThreat = await Threat.create({
      organizationId: params.organizationId,
      indicator: params.indicator.toLowerCase().trim(),
      relatedRootDomain: params.relatedRootDomain.toLowerCase().trim(),
      source: params.source,
      confidence: params.confidence,
      corroborationScore: params.corroborationScore,
      corroborationFactors: params.corroborationFactors,
      evidenceId: params.evidenceId,
      status: 'OPEN',
      dedupKey,
      firstSeen: now,
      lastSeen: now,
      resolvedIps: params.resolvedIps || [],
      registrarAge: params.registrarAge,
      hostingAsn: params.hostingAsn,
      hostingOrg: params.hostingOrg,
    });

    return { threat: newThreat, isNew: true };
  }

  // In-Memory store handling
  const storeKey = `${params.organizationId}:${dedupKey}`;
  const existing = memoryStore.threats.get(storeKey);

  if (existing) {
    existing.lastSeen = now;
    existing.corroborationScore = params.corroborationScore;
    existing.confidence = params.confidence;
    existing.corroborationFactors = params.corroborationFactors;
    if (params.evidenceId) existing.evidenceId = params.evidenceId;
    if (params.resolvedIps) existing.resolvedIps = params.resolvedIps;
    if (params.registrarAge !== undefined) existing.registrarAge = params.registrarAge;
    if (params.hostingAsn) existing.hostingAsn = params.hostingAsn;
    if (params.hostingOrg) existing.hostingOrg = params.hostingOrg;

    if (existing.status === 'RESOLVED' && params.corroborationScore >= 45) {
      existing.status = 'OPEN';
    }

    existing.updatedAt = now;
    memoryStore.threats.set(storeKey, existing);
    return { threat: existing, isNew: false };
  }

  const threatId = `threat-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const newThreat = {
    _id: threatId,
    id: threatId,
    organizationId: params.organizationId,
    indicator: params.indicator.toLowerCase().trim(),
    relatedRootDomain: params.relatedRootDomain.toLowerCase().trim(),
    source: params.source,
    confidence: params.confidence,
    corroborationScore: params.corroborationScore,
    corroborationFactors: params.corroborationFactors,
    evidenceId: params.evidenceId,
    status: 'OPEN',
    dedupKey,
    firstSeen: now,
    lastSeen: now,
    resolvedIps: params.resolvedIps || [],
    registrarAge: params.registrarAge,
    hostingAsn: params.hostingAsn,
    hostingOrg: params.hostingOrg,
    createdAt: now,
    updatedAt: now,
    save: async () => {},
  };

  memoryStore.threats.set(storeKey, newThreat);
  return { threat: newThreat, isNew: true };
}

/**
 * Creates an immutable Evidence record for a threat observation.
 */
export async function createThreatEvidence(params: {
  organizationId: string;
  checkType: 'CT_LOG_MATCH' | 'WHOIS_LOOKUP' | 'ASN_LOOKUP' | 'DNS_RECORD';
  rawObservation: any;
}): Promise<any> {
  const contentHash = crypto
    .createHash('sha256')
    .update(JSON.stringify(params.rawObservation))
    .digest('hex');

  const evidenceDoc = {
    organizationId: params.organizationId,
    assetId: undefined,
    scanId: undefined,
    checkType: params.checkType,
    rawObservation: params.rawObservation,
    contentHash,
    observedAt: new Date(),
    createdAt: new Date(),
  };

  if (isMongoActive()) {
    try {
      return await Evidence.create(evidenceDoc);
    } catch {
      return evidenceDoc;
    }
  }

  const evidenceId = `ev-${contentHash.substring(0, 12)}`;
  const fullDoc = { ...evidenceDoc, _id: evidenceId, id: evidenceId };
  memoryStore.evidence.set(contentHash, fullDoc);
  return fullDoc;
}

/**
 * Executes a full threat and brand monitoring sweep for a verified root domain.
 */
export async function runThreatMonitoring(
  options: ThreatMonitoringOptions
): Promise<ThreatMonitoringResult> {
  const normalizedRoot = options.rootDomain.toLowerCase().trim();
  const maxDns = options.maxDnsChecks ?? 30;

  console.log(`[ThreatEngine] Starting threat monitoring for domain "${normalizedRoot}"...`);

  // 1. Generate Domain Permutations (bounded depth <= 2)
  const permutations = generateDomainPermutations(normalizedRoot);

  // 2. Query Certificate Transparency logs for passive look-alike certificates
  let ctLogCandidates: string[] = [];
  try {
    const ctResult = await queryCertificateTransparency(normalizedRoot);
    ctLogCandidates = ctResult.candidates || [];
  } catch (err: any) {
    console.warn(`[ThreatEngine] CT log query warning: ${err?.message}`);
  }

  // 3. Compile Candidate Universe (bounded to prevent DNS saturation)
  const candidatePool: Array<{ domain: string; source: ThreatSource; matchType: any }> = [];
  const seenDomains = new Set<string>();

  // Add top permutations
  for (const p of permutations.slice(0, maxDns)) {
    if (!seenDomains.has(p.domain)) {
      seenDomains.add(p.domain);
      candidatePool.push({
        domain: p.domain,
        source: 'TYPOSQUAT_PERMUTATION',
        matchType: p.fuzzer === 'keyword' ? 'KEYWORD_MATCH' : p.fuzzer === 'tld_variant' ? 'TLD_VARIANT' : 'TYPOSQUAT_PERMUTATION',
      });
    }
  }

  // Add CT log candidates that match keyword or look-alikes
  const brandStem = normalizedRoot.split('.')[0];
  for (const c of ctLogCandidates) {
    if (!seenDomains.has(c) && c !== normalizedRoot && c.includes(brandStem)) {
      seenDomains.add(c);
      candidatePool.push({
        domain: c,
        source: 'CT_LOG',
        matchType: 'KEYWORD_MATCH',
      });
    }
  }

  let threatsCreated = 0;
  let threatsUpdated = 0;
  let alertsTriggered = 0;
  const processedThreats: any[] = [];

  // 4. Evaluate Candidates (DNS + RDAP + ASN Corroboration)
  for (const candidate of candidatePool) {
    try {
      // 4.1 DNS Resolution
      const dnsResult = await resolveDomainDns(candidate.domain);

      // 4.2 If live, gather corroborating RDAP and ASN signals
      let ageResult: any = {};
      let asnResult: any = { isKnownAbuseAsn: false };

      if (dnsResult.isLive) {
        // Look up domain registration age
        ageResult = await lookupDomainAge(candidate.domain).catch(() => ({}));

        // Look up ASN for the first resolved IP
        if (dnsResult.ips.length > 0) {
          asnResult = await lookupIpAsn(dnsResult.ips[0]).catch(() => ({ isKnownAbuseAsn: false }));
        }
      }

      // 4.3 Compute Corroboration Score & Confidence
      const corroboration = computeCorroborationScore({
        matchType: candidate.matchType,
        isLiveDns: dnsResult.isLive,
        resolvedIps: dnsResult.ips,
        registrarAgeDays: ageResult.ageDays,
        createdDate: ageResult.createdDate,
        registrarName: ageResult.registrar,
        hostingAsn: asnResult.asn,
        hostingOrg: asnResult.org,
        isKnownAbuseAsn: asnResult.isKnownAbuseAsn,
        isMxConfigured: dnsResult.hasMx,
        hasTlsCert: false,
      });

      // 4.4 Save immutable Evidence record
      const evidence = await createThreatEvidence({
        organizationId: options.organizationId,
        checkType: dnsResult.isLive ? 'DNS_RECORD' : 'CT_LOG_MATCH',
        rawObservation: {
          indicator: candidate.domain,
          targetDomain: normalizedRoot,
          source: candidate.source,
          dns: dnsResult,
          whois: ageResult,
          asn: asnResult,
          corroboration: corroboration.factors,
        },
      });

      // 4.5 Canonical Upsert Threat record
      const { threat, isNew } = await upsertThreatRecord({
        organizationId: options.organizationId,
        indicator: candidate.domain,
        relatedRootDomain: normalizedRoot,
        source: candidate.source,
        confidence: corroboration.confidence,
        corroborationScore: corroboration.corroborationScore,
        corroborationFactors: corroboration.factors,
        evidenceId: evidence._id || evidence.id,
        resolvedIps: dnsResult.ips,
        registrarAge: ageResult.ageDays,
        hostingAsn: asnResult.asn,
        hostingOrg: asnResult.org,
      });

      if (isNew) threatsCreated++;
      else threatsUpdated++;

      processedThreats.push(threat);

      // 4.6 Evaluate Alert Dispatching (THREAT_DETECTED)
      // Only fires for HIGH / CONFIRMED confidence, score >= 65
      if (corroboration.confidence === 'HIGH' || corroboration.confidence === 'CONFIRMED') {
        const alertRes = await triggerAlert({
          organizationId: options.organizationId,
          type: 'THREAT_DETECTED',
          targetName: candidate.domain,
          threat,
        });

        if (alertRes.triggered) {
          alertsTriggered++;
        }
      }
    } catch (candidateErr: any) {
      console.warn(`[ThreatEngine] Error evaluating candidate "${candidate.domain}":`, candidateErr?.message);
    }
  }

  // 5. Record AuditLog entry
  if (isMongoActive()) {
    await AuditLog.create({
      organizationId: options.organizationId,
      actorId: 'system:threat_monitor',
      action: 'THREAT_SCAN_COMPLETED',
      objectType: 'ThreatScan',
      objectId: `threat-scan-${Date.now()}`,
      result: 'SUCCESS',
      details: {
        rootDomain: normalizedRoot,
        candidatesEvaluated: candidatePool.length,
        threatsCreated,
        threatsUpdated,
        alertsTriggered,
      },
    });
  } else {
    memoryStore.auditLogs.push({
      organizationId: options.organizationId,
      actorId: 'system:threat_monitor',
      action: 'THREAT_SCAN_COMPLETED',
      objectType: 'ThreatScan',
      objectId: `threat-scan-${Date.now()}`,
      result: 'SUCCESS',
      details: {
        rootDomain: normalizedRoot,
        candidatesEvaluated: candidatePool.length,
        threatsCreated,
        threatsUpdated,
        alertsTriggered,
      },
      createdAt: new Date(),
    });
  }

  return {
    rootDomain: normalizedRoot,
    totalPermutationsGenerated: permutations.length,
    candidatesEvaluated: candidatePool.length,
    threatsCreated,
    threatsUpdated,
    alertsTriggered,
    threats: processedThreats,
  };
}
