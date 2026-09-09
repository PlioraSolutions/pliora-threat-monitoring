import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
import { memoryStore } from '../src/lib/store';
import { createSessionToken } from '../src/lib/auth';
import { analyzeCalibrationDrift, FindingGroupDrift } from '../src/lib/calibration/driftAnalysis';
import {
  applyCalibrationAdjustment,
  getCalibrationAdjustments,
  resetCalibrationAdjustments,
} from '../src/lib/calibration/adjustment';
import {
  computeRiskScore,
  resetScoringOverrides,
} from '../src/lib/risk/scoring';
import {
  simulateRiskScoreIfResolved,
  aggregateRiskScore,
} from '../src/lib/risk/orgScore';
import { GET as getCalibrationDrift, POST as postCalibrationAdjust } from '../src/app/api/admin/calibration/drift/route';
import { POST as simulateRiskRoute } from '../src/app/api/risk-score/simulate/route';
import { POST as submitFeedbackRoute } from '../src/app/api/findings/[id]/explain/feedback/route';
import { GET as getAiReviewSamples, POST as postAiReviewSample } from '../src/app/api/admin/ai/review-sample/route';
import {
  MultiProviderChain,
  ILLMProvider,
  CompletionOptions,
} from '../src/lib/ai/provider';
import { RawAIResponseSchema, REGISTERED_CHECK_TYPES } from '../src/lib/ai/schema';
import { computeContentSimilarity } from '../src/lib/threats/contentSimilarity';
import { computeCorroborationScore } from '../src/lib/threats/corroboration';
import { metrics } from '../src/lib/observability/metrics';

describe('Roadmap Phase B: Deepening the Moat (§B.1–§B.4)', () => {
  const testOrgId = 'org-phase-b-test-01';
  const adminUserId = 'user-phase-b-admin-01';
  let adminCookie: string;

  it('Setup: Initialize test Organization and Admin user session', async () => {
    memoryStore.organizations.set(testOrgId, {
      _id: testOrgId,
      name: 'Moat Test Corp',
      slug: 'moat-test-corp',
      plan: 'BUSINESS',
    });

    memoryStore.users.set(adminUserId, {
      _id: adminUserId,
      id: adminUserId,
      email: 'admin@moat-test.com',
      name: 'Moat Admin',
      organizationMemberships: [
        {
          organizationId: testOrgId,
          role: 'OWNER',
          joinedAt: new Date(),
        },
      ],
      activeOrganizationId: testOrgId,
    });

    const token = createSessionToken({
      userId: adminUserId,
      email: 'admin@moat-test.com',
      organizationId: testOrgId,
      role: 'OWNER',
    });
    adminCookie = `pliora_session=${token}`;
    assert(!!adminCookie, 'Session cookie initialized');
  });

  // =========================================================================
  // Test Group 1: Calibration Feedback & Drift Analysis (§B.4 — Centerpiece)
  // =========================================================================
  describe('1. Calibration Feedback & Drift Analysis (§B.4)', () => {
    it('Respects minSampleSize >= 5 threshold and flags INSUFFICIENT_DATA below volume', async () => {
      // Clear existing feedback
      memoryStore.calibrationFeedback = [];

      // Add only 3 feedback records for a rule
      for (let i = 0; i < 3; i++) {
        memoryStore.calibrationFeedback.push({
          organizationId: testOrgId,
          findingId: `f-low-${i}`,
          findingCode: 'PORT-8080-OPEN',
          category: 'EXPOSED_SERVICES',
          severityAtTriage: 'MEDIUM',
          confidenceAtTriage: 'MEDIUM',
          action: 'FALSE_POSITIVE',
          actorId: adminUserId,
          createdAt: new Date(),
        });
      }

      const report = await analyzeCalibrationDrift({ minSampleSize: 5 });
      assert.strictEqual(report.totalSamples, 3);
      const group = report.groups.find((g) => g.findingCode === 'PORT-8080-OPEN');
      assert(!!group, 'Group exists');
      assert.strictEqual(group.driftStatus, 'INSUFFICIENT_DATA');
      assert(group.recommendation?.includes('below statistical significance threshold'));
      assert.strictEqual(report.miscalibratedGroupsCount, 0, 'No miscalibration asserted without statistical volume');
    });

    it('Detects MISCALIBRATED_OVERCONFIDENT when FP rate > 15% on HIGH/CONFIRMED confidence', async () => {
      memoryStore.calibrationFeedback = [];

      // Seed 10 records: 3 False Positives (30% FP rate) on CONFIRMED findings
      for (let i = 0; i < 10; i++) {
        memoryStore.calibrationFeedback.push({
          organizationId: testOrgId,
          findingId: `f-conf-${i}`,
          findingCode: 'TLS-EXPIRED-CERT',
          category: 'TRANSPORT_SECURITY',
          severityAtTriage: 'HIGH',
          confidenceAtTriage: 'CONFIRMED',
          action: i < 3 ? 'FALSE_POSITIVE' : 'RESOLVED',
          actorId: adminUserId,
          createdAt: new Date(),
        });
      }

      const report = await analyzeCalibrationDrift({ minSampleSize: 5 });
      const group = report.groups.find((g) => g.findingCode === 'TLS-EXPIRED-CERT');
      assert(!!group, 'Found TLS-EXPIRED-CERT group');
      assert.strictEqual(group.falsePositiveRate, 0.3);
      assert.strictEqual(group.driftStatus, 'MISCALIBRATED_OVERCONFIDENT');
      assert(group.suggestedAdjustment !== undefined);
      assert.strictEqual(group.suggestedAdjustment?.targetType, 'FINDING_CODE_MULTIPLIER');
      assert.strictEqual(report.miscalibratedGroupsCount, 1);
      assert.strictEqual(report.recommendedAdjustments.length, 1);
    });

    it('Detects MISCALIBRATED_HIGH_NOISE when FP rate > 35% on MEDIUM confidence findings', async () => {
      memoryStore.calibrationFeedback = [];

      // Seed 6 records: 3 False Positives (50% FP rate) on MEDIUM findings
      for (let i = 0; i < 6; i++) {
        memoryStore.calibrationFeedback.push({
          organizationId: testOrgId,
          findingId: `f-med-${i}`,
          findingCode: 'HEADER-X-POWERED-BY',
          category: 'HTTP_SECURITY_HEADERS',
          severityAtTriage: 'MEDIUM',
          confidenceAtTriage: 'MEDIUM',
          action: i < 3 ? 'FALSE_POSITIVE' : 'ACCEPTED_RISK',
          actorId: adminUserId,
          createdAt: new Date(),
        });
      }

      const report = await analyzeCalibrationDrift({ minSampleSize: 5 });
      const group = report.groups.find((g) => g.findingCode === 'HEADER-X-POWERED-BY');
      assert(!!group);
      assert.strictEqual(group.falsePositiveRate, 0.5);
      assert.strictEqual(group.driftStatus, 'MISCALIBRATED_HIGH_NOISE');
      assert(group.recommendation?.includes('Excessive false-positive noise'));
    });

    it('Detects UNDERVALUED_FINDING when resolution rate > 85% on LOW severity', async () => {
      memoryStore.calibrationFeedback = [];

      // Seed 10 records: 9 Resolved (90% resolution rate) on LOW severity
      for (let i = 0; i < 10; i++) {
        memoryStore.calibrationFeedback.push({
          organizationId: testOrgId,
          findingId: `f-low-${i}`,
          findingCode: 'COOKIE-MISSING-SAMESITE',
          category: 'HTTP_SECURITY_HEADERS',
          severityAtTriage: 'LOW',
          confidenceAtTriage: 'LOW',
          action: i < 9 ? 'RESOLVED' : 'ACCEPTED_RISK',
          actorId: adminUserId,
          createdAt: new Date(),
        });
      }

      const report = await analyzeCalibrationDrift({ minSampleSize: 5 });
      const group = report.groups.find((g) => g.findingCode === 'COOKIE-MISSING-SAMESITE');
      assert(!!group);
      assert.strictEqual(group.resolvedRate, 0.9);
      assert.strictEqual(group.driftStatus, 'UNDERVALUED_FINDING');
      assert(group.recommendation?.includes('High customer resolution rate'));
    });

    it('Emits drift metrics into telemetry snapshot', async () => {
      const snapshot = metrics.getMetricsSnapshot();
      assert(snapshot.calibration !== undefined, 'Telemetry includes calibration metrics');
      assert(typeof snapshot.calibration.totalFeedbackSamples === 'number');
      assert(typeof snapshot.calibration.miscalibratedCount === 'number');
    });
  });

  // =========================================================================
  // Test Group 2: Human-Reviewed Calibration Weight Adjustment (§B.4)
  // =========================================================================
  describe('2. Human-Reviewed Calibration Weight Adjustment (§B.4)', () => {
    it('Rejects adjustments missing rationale or invalid value ranges', async () => {
      await assert.rejects(
        async () => {
          await applyCalibrationAdjustment({
            targetType: 'FINDING_CODE_MULTIPLIER',
            targetKey: 'TLS-EXPIRED-CERT',
            previousValue: 1.0,
            adjustedValue: -0.5, // invalid negative
            rationale: 'Valid rationale',
            actorId: adminUserId,
          });
        },
        /adjustedValue must be a valid positive number/
      );

      await assert.rejects(
        async () => {
          await applyCalibrationAdjustment({
            targetType: 'FINDING_CODE_MULTIPLIER',
            targetKey: 'TLS-EXPIRED-CERT',
            previousValue: 1.0,
            adjustedValue: 0.75,
            rationale: '', // missing rationale
            actorId: adminUserId,
          });
        },
        /A detailed human-reviewed rationale/
      );
    });

    it('Applies adjustment, writes AuditLog, and modifies computeRiskScore output', async () => {
      resetCalibrationAdjustments();
      const initialAuditCount = memoryStore.auditLogs.length;

      // Baseline score before adjustment
      const baseline = computeRiskScore(
        { severity: 'HIGH', confidence: 'CONFIRMED', findingCode: 'TLS-EXPIRED-CERT' },
        { fqdn: 'sub.acme.test', type: 'SUBDOMAIN', importance: 'HIGH' }
      );

      // Apply adjustment: dampen multiplier to 0.70 based on drift analysis
      const result = await applyCalibrationAdjustment({
        targetType: 'FINDING_CODE_MULTIPLIER',
        targetKey: 'TLS-EXPIRED-CERT',
        previousValue: 1.0,
        adjustedValue: 0.7,
        rationale: 'Dampen overconfident TLS rule based on 30% FP rate in production feedback',
        actorId: adminUserId,
      });

      assert.strictEqual(result.success, true);
      assert(!!result.auditLogId);

      // Verify AuditLog written
      const calLog = memoryStore.auditLogs.find(
        (l) => l.action === 'CALIBRATION_WEIGHTS_ADJUSTED' && l.objectId === 'FINDING_CODE_MULTIPLIER::TLS-EXPIRED-CERT'
      );
      assert(!!calLog, 'AuditLog created for calibration adjustment');
      assert.strictEqual(calLog.details.adjustedValue, 0.7);

      // Verify modified score
      const adjusted = computeRiskScore(
        { severity: 'HIGH', confidence: 'CONFIRMED', findingCode: 'TLS-EXPIRED-CERT' },
        { fqdn: 'sub.acme.test', type: 'SUBDOMAIN', importance: 'HIGH' }
      );

      assert(adjusted.score < baseline.score, 'Adjusted score is dampened by multiplier');
      assert.strictEqual(adjusted.factors.findingMultiplier, 0.7);

      // Reset overrides for test hygiene
      resetScoringOverrides();
    });

    it('GET & POST /api/admin/calibration/drift endpoint works as expected', async () => {
      // Test GET drift
      const reqGet = new NextRequest('http://localhost:3000/api/admin/calibration/drift?minSampleSize=3', {
        method: 'GET',
        headers: { cookie: adminCookie },
      });
      const resGet = await getCalibrationDrift(reqGet);
      assert.strictEqual(resGet.status, 200);
      const jsonGet = await resGet.json();
      assert.strictEqual(jsonGet.success, true);
      assert(jsonGet.data.report !== undefined);

      // Test POST adjust
      const reqPost = new NextRequest('http://localhost:3000/api/admin/calibration/drift', {
        method: 'POST',
        headers: {
          cookie: adminCookie,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          targetType: 'CONFIDENCE_WEIGHT',
          targetKey: 'CONFIRMED',
          previousValue: 1.0,
          adjustedValue: 0.95,
          rationale: 'Slight platform-wide conservative confidence adjustment',
        }),
      });

      const resPost = await postCalibrationAdjust(reqPost);
      assert.strictEqual(resPost.status, 200);
      const jsonPost = await resPost.json();
      assert.strictEqual(jsonPost.success, true);
      assert.strictEqual(jsonPost.data.adjustment.targetKey, 'CONFIRMED');

      resetScoringOverrides();
    });
  });

  // =========================================================================
  // Test Group 3: What-If Risk Score Simulation (§B.3 / §4.1)
  // =========================================================================
  describe('3. What-If Risk Score Simulation (§B.3)', () => {
    const simFinding1 = 'f-sim-01';
    const simFinding2 = 'f-sim-02';

    it('Calculates score and posture improvements with ZERO side effects', async () => {
      // Seed findings into store
      memoryStore.findings.set(simFinding1, {
        _id: simFinding1,
        id: simFinding1,
        organizationId: testOrgId,
        severity: 'CRITICAL',
        confidence: 'CONFIRMED',
        status: 'OPEN',
        riskScore: 85,
      });

      memoryStore.findings.set(simFinding2, {
        _id: simFinding2,
        id: simFinding2,
        organizationId: testOrgId,
        severity: 'HIGH',
        confidence: 'HIGH',
        status: 'OPEN',
        riskScore: 60,
      });

      const initialSnapshotCount = memoryStore.riskScoreSnapshots.length;
      const initialFinding1Status = memoryStore.findings.get(simFinding1).status;
      const initialAuditCount = memoryStore.auditLogs.length;

      // Run simulation resolving simFinding1
      const simulation = await simulateRiskScoreIfResolved(testOrgId, [simFinding1]);

      assert.strictEqual(simulation.resolvedFindingCount, 1);
      assert(simulation.scoreDelta > 0, 'Risk score decreased upon hypothetical resolution');
      assert(simulation.postureDelta > 0, 'Security posture increased upon hypothetical resolution');
      assert(simulation.simulated.securityPosture > simulation.current.securityPosture);

      // STRICT READ-ONLY INVARIANT ASSERTIONS
      assert.strictEqual(
        memoryStore.findings.get(simFinding1).status,
        initialFinding1Status,
        'CRITICAL INVARIANT: Finding document in database/store was NOT mutated'
      );
      assert.strictEqual(
        memoryStore.riskScoreSnapshots.length,
        initialSnapshotCount,
        'CRITICAL INVARIANT: Zero RiskScoreSnapshot records written during simulation'
      );
      assert.strictEqual(
        memoryStore.auditLogs.length,
        initialAuditCount,
        'CRITICAL INVARIANT: Zero AuditLog records written during simulation'
      );
    });

    it('POST /api/risk-score/simulate endpoint returns projection', async () => {
      const req = new NextRequest('http://localhost:3000/api/risk-score/simulate', {
        method: 'POST',
        headers: {
          cookie: adminCookie,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          findingIds: [simFinding1, simFinding2],
        }),
      });

      const res = await simulateRiskRoute(req);
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.success, true);
      assert.strictEqual(json.data.resolvedFindingCount, 2);
      assert(json.data.postureDelta > 0);
    });
  });

  // =========================================================================
  // Test Group 4: Grounded AI Multi-Provider Fallback Chain (§B.1 / §2.1)
  // =========================================================================
  describe('4. Grounded AI Multi-Provider Fallback Chain (§B.1)', () => {
    class FailingProvider implements ILLMProvider {
      readonly providerName = 'failing-primary';
      async generateStructuredCompletion<T>(): Promise<T> {
        throw new Error('Primary upstream provider connection timeout');
      }
    }

    class WorkingSecondaryProvider implements ILLMProvider {
      readonly providerName = 'working-secondary';
      async generateStructuredCompletion<T>(): Promise<T> {
        return {
          explanation: 'Secondary provider successfully produced explanation.',
          businessImpact: 'Business impact assessed by fallback model.',
          remediationSteps: ['Step 1: Check configurations.'],
          citedEvidenceFields: ['severity'],
        } as T;
      }
    }

    it('MultiProviderChain falls over to secondary provider when primary fails', async () => {
      const primary = new FailingProvider();
      const secondary = new WorkingSecondaryProvider();
      const chain = new MultiProviderChain([primary, secondary]);

      const result = await chain.generateStructuredCompletion<any>({
        systemPrompt: 'System',
        userPrompt: 'User',
      });

      assert(!!result);
      assert.strictEqual(result.explanation, 'Secondary provider successfully produced explanation.');
      assert.strictEqual(chain.getLastServedProvider(), 'working-secondary');
    });

    it('Throws when all providers in chain fail, allowing analyst service template fallback', async () => {
      const primary = new FailingProvider();
      const secondary = new FailingProvider();
      const chain = new MultiProviderChain([primary, secondary]);

      await assert.rejects(
        async () => {
          await chain.generateStructuredCompletion({ systemPrompt: '', userPrompt: '' });
        },
        /MultiProviderChain exhausted all providers/
      );
    });
  });

  // =========================================================================
  // Test Group 5: Bounded Investigate Signal (§B.1 / §2.2)
  // =========================================================================
  describe('5. Bounded Investigate Signal (§B.1 / §2.2)', () => {
    it('Validates allowed CheckType in requestedEvidence schema', () => {
      const validPayload = {
        explanation: 'Valid explanation text for testing purposes.',
        businessImpact: 'Valid business impact text here.',
        remediationSteps: ['Step 1: Rotate keys'],
        citedEvidenceFields: ['findingCode'],
        requestedEvidence: 'TLS_HANDSHAKE',
      };

      const parsed = RawAIResponseSchema.safeParse(validPayload);
      assert.strictEqual(parsed.success, true);
      if (parsed.success) {
        assert.strictEqual(parsed.data.requestedEvidence, 'TLS_HANDSHAKE');
      }
    });

    it('Strictly rejects unapproved / invented check types outside registered enum', () => {
      const invalidPayload = {
        explanation: 'Valid explanation text for testing purposes.',
        businessImpact: 'Valid business impact text here.',
        remediationSteps: ['Step 1: Rotate keys'],
        citedEvidenceFields: ['findingCode'],
        requestedEvidence: 'UNAPPROVED_CUSTOM_PROBE_HACK',
      };

      const parsed = RawAIResponseSchema.safeParse(invalidPayload);
      assert.strictEqual(parsed.success, false, 'Invented check type must fail Zod validation');
    });
  });

  // =========================================================================
  // Test Group 6: Explanation Quality Feedback & Review Sampling (§B.1)
  // =========================================================================
  describe('6. Explanation Quality Feedback & Review Sampling (§B.1)', () => {
    it('POST /api/findings/[id]/explain/feedback captures user rating and creates AuditLog', async () => {
      const targetFindingId = 'f-sim-01';
      const req = new NextRequest(`http://localhost:3000/api/findings/${targetFindingId}/explain/feedback`, {
        method: 'POST',
        headers: {
          cookie: adminCookie,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          rating: 'HELPFUL',
          comment: 'Very clear explanation of TLS posture.',
          modelName: 'gemini-1.5-flash',
        }),
      });

      const res = await submitFeedbackRoute(req, { params: Promise.resolve({ id: targetFindingId }) });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.success, true);
      assert.strictEqual(json.data.rating, 'HELPFUL');

      // Verify AuditLog
      const auditEntry = memoryStore.auditLogs.find(
        (l) => l.action === 'AI_EXPLANATION_FEEDBACK_RECORDED' && l.objectId === targetFindingId
      );
      assert(!!auditEntry, 'AuditLog created for feedback');
    });

    it('Admin AI review sampling GET & POST endpoints record spot-check review', async () => {
      // Seed a cache entry
      memoryStore.aiExplanations.set('sample-test-key-01', {
        explanation: 'Test cached explanation',
        businessImpact: 'Impact',
        modelName: 'mock',
      });

      // 1. GET samples
      const reqGet = new NextRequest('http://localhost:3000/api/admin/ai/review-sample', {
        method: 'GET',
        headers: { cookie: adminCookie },
      });
      const resGet = await getAiReviewSamples(reqGet);
      assert.strictEqual(resGet.status, 200);
      const jsonGet = await resGet.json();
      assert.strictEqual(jsonGet.success, true);
      assert(jsonGet.data.samples.length > 0);

      // 2. POST review decision
      const reqPost = new NextRequest('http://localhost:3000/api/admin/ai/review-sample', {
        method: 'POST',
        headers: {
          cookie: adminCookie,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          sampleId: 'sample-test-key-01',
          status: 'APPROVED',
          notes: 'High fidelity grounding confirmed',
        }),
      });
      const resPost = await postAiReviewSample(reqPost);
      assert.strictEqual(resPost.status, 200);
      const jsonPost = await resPost.json();
      assert.strictEqual(jsonPost.success, true);
      assert.strictEqual(jsonPost.data.status, 'APPROVED');

      // Verify AuditLog
      const auditLog = memoryStore.auditLogs.find(
        (l) => l.action === 'AI_EXPLANATION_HUMAN_REVIEWED' && l.objectId === 'sample-test-key-01'
      );
      assert(!!auditLog, 'AuditLog created for human review of AI sample');
    });
  });

  // =========================================================================
  // Test Group 7: Typosquat Structural Content Similarity (§B.2)
  // =========================================================================
  describe('7. Typosquat Structural Content Similarity (§B.2)', () => {
    const legitHtml = `
      <!DOCTYPE html>
      <html>
        <head><title>Acme Portal</title><link href="/assets/styles.css" rel="stylesheet"></head>
        <body>
          <header><nav><a href="/">Home</a><img src="/img/brand-logo.png" /></nav></header>
          <main>
            <form action="/login" method="POST">
              <input type="text" name="username" placeholder="Username" />
              <input type="password" name="password" placeholder="Password" />
              <button type="submit">Sign In</button>
            </form>
          </main>
          <footer><p>&copy; 2026 Acme Corp</p></footer>
        </body>
      </html>
    `;

    const clonePhishingHtml = `
      <html>
        <head><link href="https://acme.com/assets/styles.css" rel="stylesheet"></head>
        <body>
          <header><nav><img src="/img/brand-logo.png" /></nav></header>
          <div class="login-box">
            <form action="/harvest" method="POST">
              <input type="text" name="username" />
              <input type="password" name="password" />
              <button type="submit">Log In</button>
            </form>
          </div>
          <footer><p>Acme Security</p></footer>
        </body>
      </html>
    `;

    const unrelatedHtml = `
      <html>
        <body>
          <h1>Welcome to personal blog</h1>
          <article><p>Hello world.</p></article>
        </body>
      </html>
    `;

    it('computeContentSimilarity accurately identifies matching login form and shared assets', () => {
      const sim = computeContentSimilarity(legitHtml, clonePhishingHtml);
      assert.strictEqual(sim.hasMatchingLoginForm, true, 'Detects matching credential form');
      assert.strictEqual(sim.hasSharedAssets, true, 'Detects shared brand assets');
      assert(sim.sharedAssetNames.includes('brand-logo.png'));
      assert(sim.similarityScore >= 60, `High structural score: ${sim.similarityScore}`);
    });

    it('computeContentSimilarity gives low score for unrelated site', () => {
      const sim = computeContentSimilarity(legitHtml, unrelatedHtml);
      assert.strictEqual(sim.hasMatchingLoginForm, false);
      assert.strictEqual(sim.hasSharedAssets, false);
      assert(sim.similarityScore < 40, `Low structural score: ${sim.similarityScore}`);
    });

    it('computeCorroborationScore integrates content similarity points on live domains', () => {
      // Resolving domain without similarity
      const baseResult = computeCorroborationScore({
        matchType: 'TYPOSQUAT_PERMUTATION',
        editDistance: 1,
        isLiveDns: true,
        registrarAgeDays: 10,
        hasTlsCert: true,
      });

      // Resolving domain WITH phishing login form & structural similarity
      const similarityResult = computeCorroborationScore({
        matchType: 'TYPOSQUAT_PERMUTATION',
        editDistance: 1,
        isLiveDns: true,
        registrarAgeDays: 10,
        hasTlsCert: true,
        contentSimilarity: {
          similarityScore: 85,
          hasMatchingLoginForm: true,
          hasSharedAssets: true,
        },
      });

      assert(similarityResult.factors.breakdown?.similarityPoints !== undefined);
      assert(similarityResult.factors.breakdown.similarityPoints >= 20, 'Awarded >= 20 similarity points');
      assert(similarityResult.corroborationScore > baseResult.corroborationScore);
      assert.strictEqual(similarityResult.confidence, 'CONFIRMED');
      assert(similarityResult.reason.includes('cloned login/credential harvesting form detected'));
    });

    it('Non-resolving domains remain capped at INFORMATIONAL regardless of similarity factor', () => {
      const nonResolving = computeCorroborationScore({
        matchType: 'KEYWORD_MATCH',
        isLiveDns: false,
        contentSimilarity: {
          similarityScore: 95,
          hasMatchingLoginForm: true,
        },
      });

      assert.strictEqual(nonResolving.confidence, 'INFORMATIONAL', 'Non-resolving domain strictly capped');
      assert(nonResolving.corroborationScore <= 24);
      assert.strictEqual(nonResolving.factors.breakdown?.similarityPoints, 0);
    });
  });
});
