import { connectToDatabase, isMongoActive } from '@/lib/db';
import { Scan, IPluginRun } from '@/models/Scan';
import { Asset } from '@/models/Asset';
import { Evidence } from '@/models/Evidence';
import { Finding } from '@/models/Finding';
import { AuditLog } from '@/models/AuditLog';
import { CalibrationFeedback } from '@/models/CalibrationFeedback';
import { assertSafeTargetHostname, safeFetch, safeTlsHandshake, safeTcpConnect } from '@/lib/security';
import { ScanJobData } from '@/lib/queue';
import { memoryStore } from '@/lib/store';
import { pluginRegistry } from '@/lib/plugins/registry';
import { PluginContext, PluginResult } from '@/lib/plugins/types';
import { evidenceToFindings, computeFindingDedupHash } from '@/lib/plugins/findings';
import { computeRiskScore } from '@/lib/risk/computeRiskScore';
import { computeOrgRiskScore, recordRiskScoreSnapshot } from '@/lib/risk/orgScore';
import { runPassiveDiscovery } from '@/lib/discovery/engine';
import { triggerAlert } from '@/lib/alerts/service';
import dns from 'dns/promises';
import crypto from 'crypto';
import { logger } from '@/lib/observability/logger';
import { errorTracker } from '@/lib/observability/errorTracker';
import { metrics } from '@/lib/observability/metrics';

/**
 * Executes a single check plugin with timeout and safety boundary.
 */
async function executePluginWithTimeout(
  plugin: any,
  asset: any,
  ctx: PluginContext
): Promise<PluginResult> {
  const timeoutMs = ctx.timeoutMs || 10000;
  const start = Date.now();

  const timeoutPromise = new Promise<PluginResult>((resolve) => {
    setTimeout(() => {
      resolve({
        status: 'FAILED',
        evidence: [],
        findings: [],
        error: `Plugin "${plugin.id}" exceeded execution timeout limit (${timeoutMs}ms).`,
        durationMs: Date.now() - start,
      });
    }, timeoutMs);
  });

  try {
    const pluginPromise = plugin.run(asset, ctx).catch((err: any) => ({
      status: 'FAILED',
      evidence: [],
      findings: [],
      error: err.message || `Plugin "${plugin.id}" threw an unhandled error.`,
      durationMs: Date.now() - start,
    }));

    return await Promise.race([pluginPromise, timeoutPromise]);
  } catch (err: any) {
    return {
      status: 'FAILED',
      evidence: [],
      findings: [],
      error: err.message || 'Execution error',
      durationMs: Date.now() - start,
    };
  }
}

/**
 * Core background scan processor executed by BullMQ or memory queue.
 * Implements Multi-Step Job Pipeline (Pillar 2 §1.2 & §2.3).
 */
export async function processScanJob(data: ScanJobData): Promise<void> {
  await connectToDatabase();

  let scan: any;
  let asset: any;

  if (isMongoActive()) {
    scan = await Scan.findById(data.scanId);
    asset = await Asset.findById(data.assetId);
  } else {
    scan = memoryStore.scans.get(data.scanId);
    asset = memoryStore.assets.get(data.assetId);
  }

  if (!scan || !asset) {
    console.error(`[ScanWorker] Scan or Asset record not found: ${data.scanId}`);
    return;
  }

  // Stage 1: Verification gate (10%)
  const isVerifiableForScan =
    asset.verificationStatus === 'VERIFIED' ||
    asset.verificationStatus === 'INHERITED_VERIFIED';

  if (!isVerifiableForScan) {
    scan.status = 'FAILED';
    scan.error = `CRITICAL: Asset "${asset.fqdn}" is not verified (status: ${asset.verificationStatus}). Active scan aborted.`;
    scan.completedAt = new Date();
    if (isMongoActive()) await scan.save();

    triggerAlert({
      organizationId: scan.organizationId.toString(),
      type: 'SCAN_FAILED',
      targetName: asset.fqdn,
      asset,
      scan,
      error: scan.error,
    }).catch(() => {});

    return;
  }

  try {
    scan.status = 'ACTIVE';
    scan.progress = 10;
    scan.startedAt = new Date();
    scan.pluginRuns = [];
    if (isMongoActive()) await scan.save();
    metrics.recordScanStarted();
    logger.info(`[ScanWorker] [Stage 1: 10%] Verified asset ${asset.fqdn}. Starting discovery...`, {
      scanId: scan._id?.toString() || scan.id,
      assetId: asset._id?.toString() || asset.id,
      fqdn: asset.fqdn,
    });

    // Stage 2: Discovery & SSRF Pre-flight (30%)
    const resolvedIps = await assertSafeTargetHostname(asset.fqdn);
    asset.ipAddresses = Array.from(new Set([...(asset.ipAddresses || []), ...resolvedIps]));
    asset.lastSeen = new Date();
    if (isMongoActive()) await asset.save();

    let aRecords: string[] = [];
    let mxRecords: any[] = [];
    let txtRecords: string[][] = [];

    try {
      aRecords = await dns.resolve4(asset.fqdn);
    } catch {}
    try {
      mxRecords = await dns.resolveMx(asset.fqdn);
    } catch {}
    try {
      txtRecords = await dns.resolveTxt(asset.fqdn);
    } catch {}

    const rawDnsObservation = {
      fqdn: asset.fqdn,
      resolvedIps,
      aRecords,
      mxRecords,
      txtRecords: txtRecords.map((t) => t.join('')),
      timestamp: new Date().toISOString(),
    };

    const dnsContentHash = crypto
      .createHash('sha256')
      .update(JSON.stringify(rawDnsObservation))
      .digest('hex');

    const dnsEvidence = {
      organizationId: scan.organizationId,
      assetId: asset._id,
      scanId: scan._id,
      checkType: 'DNS_RECORD',
      rawObservation: rawDnsObservation,
      contentHash: dnsContentHash,
      observedAt: new Date(),
    };

    if (isMongoActive()) {
      await Evidence.create(dnsEvidence);
    } else {
      memoryStore.evidence.set(dnsContentHash, dnsEvidence);
    }

    scan.progress = 30;
    scan.counters.checksCompleted = 1;
    if (isMongoActive()) await scan.save();

    console.log(`[ScanWorker] [Stage 2: 30%] DNS discovery complete for ${asset.fqdn}. Pinned IPs: ${resolvedIps.join(', ')}`);

    // If scanType is DISCOVERY or FULL_SWEEP on a root domain, run passive discovery
    if (data.scanType === 'DISCOVERY' || (data.scanType === 'FULL_SWEEP' && asset.type === 'ROOT_DOMAIN')) {
      try {
        console.log(`[ScanWorker] [Stage 2] Running passive asset discovery for root domain ${asset.rootDomain || asset.fqdn}...`);
        await runPassiveDiscovery({
          organizationId: scan.organizationId.toString(),
          rootDomain: asset.rootDomain || asset.fqdn,
          parentVerified: isVerifiableForScan,
        });
      } catch (discErr: any) {
        console.warn(`[ScanWorker] Passive discovery warning: ${discErr.message}`);
      }
    }

    // Stage 3: Dynamic Plugin Execution (30% -> 70%)
    const applicablePlugins = pluginRegistry.getApplicablePlugins(asset);
    console.log(`[ScanWorker] Running ${applicablePlugins.length} applicable exposure check plugins...`);

    const pluginContext: PluginContext = {
      safeFetch,
      safeTlsHandshake,
      safeTcpConnect,
      scanId: scan._id.toString(),
      organizationId: scan.organizationId.toString(),
      timeoutMs: 8000,
    };

    const pluginRunsSummary: IPluginRun[] = [];
    const allCollectedEvidence: Array<{ checkType: any; rawObservation: any }> = [];
    const allGeneratedFindings: any[] = [];
    let hasPluginFailureOrInconclusive = false;

    for (let i = 0; i < applicablePlugins.length; i++) {
      const plugin = applicablePlugins[i];
      console.log(`[ScanWorker] [Stage 3: ${scan.progress}%] Executing plugin "${plugin.name}" (${plugin.id})...`);

      const result = await executePluginWithTimeout(plugin, asset, pluginContext);

      const findingsFromPlugin = evidenceToFindings(
        result.evidence[0] || { checkType: 'SERVICE_BANNER', rawObservation: {} },
        result.findings,
        plugin,
        asset
      );

      allCollectedEvidence.push(...result.evidence);
      allGeneratedFindings.push(...findingsFromPlugin);

      const runRecord: IPluginRun = {
        pluginId: plugin.id,
        status: result.status,
        findingsCount: findingsFromPlugin.length,
        error: result.error,
        durationMs: result.durationMs,
      };

      pluginRunsSummary.push(runRecord);

      if (result.status === 'FAILED' || result.status === 'INCONCLUSIVE') {
        hasPluginFailureOrInconclusive = true;
      }

      // Proportional progress scaling in 30-70% band
      scan.progress = Math.min(70, Math.round(30 + ((i + 1) / applicablePlugins.length) * 40));
      scan.counters.checksCompleted += 1;
      scan.pluginRuns = pluginRunsSummary;
      if (isMongoActive()) await scan.save();
    }

    // Stage 4: Writing Evidence & Deduplicating Findings (90%)
    scan.progress = 90;
    if (isMongoActive()) await scan.save();
    console.log(`[ScanWorker] [Stage 4: 90%] Persisting ${allCollectedEvidence.length} evidence items and ${allGeneratedFindings.length} findings...`);

    // 4.1 Write all Evidence records
    for (const ev of allCollectedEvidence) {
      const contentHash = crypto
        .createHash('sha256')
        .update(JSON.stringify(ev.rawObservation))
        .digest('hex');

      const evidenceDoc = {
        organizationId: scan.organizationId,
        assetId: asset._id,
        scanId: scan._id,
        checkType: ev.checkType,
        rawObservation: ev.rawObservation,
        contentHash,
        observedAt: new Date(),
      };

      if (isMongoActive()) {
        await Evidence.create(evidenceDoc).catch(() => {}); // immutable, duplicate contentHash is fine
      } else {
        memoryStore.evidence.set(contentHash, evidenceDoc);
      }
    }

    // 4.2 Deduplicate & Persist Findings with Risk Scoring
    let newFindingsCount = 0;
    for (const f of allGeneratedFindings) {
      const dedupHash = computeFindingDedupHash(
        scan.organizationId.toString(),
        asset._id.toString(),
        f.findingCode
      );

      // Compute normalized risk score based on severity, confidence, exposure, and asset importance
      const riskCalculation = computeRiskScore(
        {
          severity: f.severity,
          confidence: f.confidence,
          category: f.category,
          findingCode: f.findingCode,
        },
        asset
      );
      const computedRiskScore = riskCalculation.score;

      if (isMongoActive()) {
        const existingFinding = await Finding.findOne({
          organizationId: scan.organizationId,
          dedupHash,
        });

        if (existingFinding) {
          const previousSeverity = existingFinding.severity;
          existingFinding.lastSeen = new Date();
          existingFinding.riskScore = computedRiskScore;

          // Auto-reopen only if previously RESOLVED (never reopen ACCEPTED_RISK per §1.4)
          if (existingFinding.status === 'RESOLVED') {
            existingFinding.status = 'OPEN';
            await AuditLog.create({
              organizationId: scan.organizationId,
              actorId: 'system:scan_processor',
              action: 'FINDING_AUTO_REOPENED',
              objectType: 'Finding',
              objectId: existingFinding._id.toString(),
              result: 'SUCCESS',
              details: {
                scanId: scan._id.toString(),
                findingCode: f.findingCode,
                reason: 'Re-detected by scan after prior resolution',
              },
            });

            await CalibrationFeedback.create({
              organizationId: scan.organizationId,
              findingId: existingFinding._id,
              findingCode: f.findingCode,
              category: f.category,
              severityAtTriage: f.severity,
              confidenceAtTriage: f.confidence,
              action: 'REOPENED',
              actorId: 'system:scan_processor',
              reason: 'Re-detected by scan after prior resolution',
            });

            triggerAlert({
              organizationId: scan.organizationId.toString(),
              type: 'FINDING_AUTO_REOPENED',
              targetName: asset.fqdn,
              finding: existingFinding,
              asset,
              scan,
            }).catch(() => {});
          } else if (f.severity !== previousSeverity) {
            existingFinding.severity = f.severity;
            triggerAlert({
              organizationId: scan.organizationId.toString(),
              type: f.severity === 'CRITICAL' ? 'NEW_CRITICAL_FINDING' : 'NEW_HIGH_FINDING',
              targetName: asset.fqdn,
              finding: existingFinding,
              asset,
              scan,
            }).catch(() => {});
          }

          await existingFinding.save();
        } else {
          const createdFinding = await Finding.create({
            organizationId: scan.organizationId,
            assetId: asset._id,
            evidenceId: scan._id,
            category: f.category,
            findingCode: f.findingCode,
            title: f.title,
            description: f.description,
            severity: f.severity,
            confidence: f.confidence,
            riskScore: computedRiskScore,
            status: 'OPEN',
            dedupHash,
            remediationGuidance: f.remediationGuidance,
            firstSeen: new Date(),
            lastSeen: new Date(),
          });
          newFindingsCount++;

          triggerAlert({
            organizationId: scan.organizationId.toString(),
            type: f.severity === 'CRITICAL' ? 'NEW_CRITICAL_FINDING' : 'NEW_HIGH_FINDING',
            targetName: asset.fqdn,
            finding: createdFinding,
            asset,
            scan,
          }).catch(() => {});
        }
      } else {
        const storeKey = `${scan.organizationId}:${dedupHash}`;
        const existingFinding = memoryStore.findings.get(storeKey);

        if (existingFinding) {
          const previousSeverity = existingFinding.severity;
          existingFinding.lastSeen = new Date();
          existingFinding.riskScore = computedRiskScore;

          // Auto-reopen only if previously RESOLVED
          if (existingFinding.status === 'RESOLVED') {
            existingFinding.status = 'OPEN';
            memoryStore.auditLogs.push({
              organizationId: scan.organizationId,
              actorId: 'system:scan_processor',
              action: 'FINDING_AUTO_REOPENED',
              objectType: 'Finding',
              objectId: existingFinding._id.toString(),
              result: 'SUCCESS',
              details: {
                scanId: scan._id.toString(),
                findingCode: f.findingCode,
                reason: 'Re-detected by scan after prior resolution',
              },
              createdAt: new Date(),
            });

            memoryStore.calibrationFeedback.push({
              organizationId: scan.organizationId,
              findingId: existingFinding._id,
              findingCode: f.findingCode,
              category: f.category,
              severityAtTriage: f.severity,
              confidenceAtTriage: f.confidence,
              action: 'REOPENED',
              actorId: 'system:scan_processor',
              reason: 'Re-detected by scan after prior resolution',
              createdAt: new Date(),
            });

            triggerAlert({
              organizationId: scan.organizationId.toString(),
              type: 'FINDING_AUTO_REOPENED',
              targetName: asset.fqdn,
              finding: existingFinding,
              asset,
              scan,
            }).catch(() => {});
          } else if (f.severity !== previousSeverity) {
            existingFinding.severity = f.severity;
            triggerAlert({
              organizationId: scan.organizationId.toString(),
              type: f.severity === 'CRITICAL' ? 'NEW_CRITICAL_FINDING' : 'NEW_HIGH_FINDING',
              targetName: asset.fqdn,
              finding: existingFinding,
              asset,
              scan,
            }).catch(() => {});
          }
        } else {
          const findingDoc = {
            _id: `finding-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
            organizationId: scan.organizationId,
            assetId: asset._id,
            evidenceId: scan._id,
            category: f.category,
            findingCode: f.findingCode,
            title: f.title,
            description: f.description,
            severity: f.severity,
            confidence: f.confidence,
            riskScore: computedRiskScore,
            status: 'OPEN',
            dedupHash,
            remediationGuidance: f.remediationGuidance,
            firstSeen: new Date(),
            lastSeen: new Date(),
            createdAt: new Date(),
            updatedAt: new Date(),
          };
          memoryStore.findings.set(storeKey, findingDoc);
          newFindingsCount++;

          triggerAlert({
            organizationId: scan.organizationId.toString(),
            type: f.severity === 'CRITICAL' ? 'NEW_CRITICAL_FINDING' : 'NEW_HIGH_FINDING',
            targetName: asset.fqdn,
            finding: findingDoc,
            asset,
            scan,
          }).catch(() => {});
        }
      }
    }

    scan.counters.findingsCreated = newFindingsCount;

    // Stage 5: Final Status & Completion (100%)
    scan.progress = 100;
    scan.completedAt = new Date();
    scan.pluginRuns = pluginRunsSummary;

    if (hasPluginFailureOrInconclusive) {
      scan.status = 'PARTIAL';
      const failingPlugins = pluginRunsSummary
        .filter((r) => r.status !== 'COMPLETED')
        .map((r) => `${r.pluginId} (${r.status}${r.error ? ': ' + r.error : ''})`)
        .join(', ');
      scan.error = `Scan completed with partial plugin results: ${failingPlugins}`;
      console.warn(`[ScanWorker] [Stage 5: 100%] Scan finished as PARTIAL for ${asset.fqdn}. Reason: ${scan.error}`);
    } else {
      scan.status = 'COMPLETED';
      console.log(`[ScanWorker] [Stage 5: 100%] Scan fully COMPLETED for ${asset.fqdn} (Findings: ${newFindingsCount}).`);
    }

    // Recompute organization risk score and record point-in-time snapshot
    try {
      const orgScore = await computeOrgRiskScore(scan.organizationId.toString());
      await recordRiskScoreSnapshot(
        scan.organizationId.toString(),
        orgScore,
        'SCAN_COMPLETED',
        scan._id.toString()
      );
      const duration = Date.now() - (scan.startedAt ? new Date(scan.startedAt).getTime() : Date.now());
      metrics.recordScanCompleted('COMPLETED', duration);
      logger.info(
        `[ScanWorker] [Stage 5: 100%] Org risk score updated: ${orgScore.score}/100 (Posture: ${orgScore.securityPosture}, Grade: ${orgScore.grade}).`,
        { scanId: scan._id?.toString() || scan.id, durationMs: duration }
      );
    } catch (scoreErr) {
      logger.warn('[ScanWorker] Failed to compute/snapshot org risk score', { error: String(scoreErr) });
    }

    if (isMongoActive()) await scan.save();
  } catch (err: any) {
    const duration = Date.now() - (scan.startedAt ? new Date(scan.startedAt).getTime() : Date.now());
    metrics.recordScanCompleted('FAILED', duration);
    errorTracker.captureScanFailure(
      scan._id?.toString() || scan.id || 'unknown',
      asset?.fqdn || 'Unknown Target',
      err,
      scan.organizationId?.toString()
    );
    scan.status = 'FAILED';
    scan.error = err.message || 'Fatal scan error';
    scan.completedAt = new Date();
    if (isMongoActive()) await scan.save();

    triggerAlert({
      organizationId: scan.organizationId.toString(),
      type: 'SCAN_FAILED',
      targetName: asset?.fqdn || 'Unknown Target',
      asset,
      scan,
      error: scan.error,
    }).catch(() => {});
  }
}

