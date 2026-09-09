import assert from 'assert';
import { getMockProvider, MockLLMProvider, getLLMProvider } from '../src/lib/ai/provider';
import { RawAIResponseSchema, getConfidenceCaveat, CONFIDENCE_CAVEATS } from '../src/lib/ai/schema';
import { REMEDIATION_LIBRARY, validateRemediationSteps } from '../src/lib/ai/remediationLibrary';
import { validateEvidenceGrounding } from '../src/lib/ai/groundingChecker';
import {
  buildFindingExplanationPrompt,
  buildThreatExplanationPrompt,
  buildExecutiveSummaryPrompt,
} from '../src/lib/ai/prompts';
import {
  generateFindingFallback,
  generateThreatFallback,
  generateExecutiveSummaryFallback,
} from '../src/lib/ai/fallback';
import {
  explainFinding,
  explainThreat,
  generateExecutiveSummary,
} from '../src/lib/ai/analystService';
import { memoryStore } from '../src/lib/store';
import { createSessionToken } from '../src/lib/auth';
import { GET as getFindingExplain } from '../src/app/api/findings/[id]/explain/route';
import { GET as getThreatExplain } from '../src/app/api/threats/[id]/explain/route';
import { GET as getExecutiveSummary } from '../src/app/api/reports/executive-summary/route';
import { NextRequest } from 'next/server';

let passed = 0;
let failed = 0;

function pass(name: string) {
  passed++;
  console.log(`  ✅ PASS: ${name}`);
}

function fail(name: string, err: any) {
  failed++;
  console.error(`  ❌ FAIL: ${name}:`, err?.message || err);
}

async function runTests() {
  console.log('🤖 Running Option 7: Grounded AI Security Analyst (Pillar 5) Tests...\n');

  const mock = getMockProvider();

  // -------------------------------------------------------------
  // Test Suite 1: Provider Abstraction & Structured Schema Validation
  // -------------------------------------------------------------
  console.log('--- Test Suite 1: Provider Abstraction & Structured Schema Validation ---');
  try {
    const provider = getLLMProvider('mock');
    assert.strictEqual(provider.providerName, 'mock');
    pass('Factory returns MockLLMProvider for mock/test environment');

    const completion = await provider.generateStructuredCompletion<any>({
      systemPrompt: 'System test',
      userPrompt: 'Explain finding: MISSING_HSTS_HEADER',
    });

    const parsed = RawAIResponseSchema.safeParse(completion);
    assert.strictEqual(parsed.success, true);
    if (parsed.success) {
      assert.ok(parsed.data.explanation.length >= 10);
      assert.ok(parsed.data.businessImpact.length >= 10);
      assert.ok(parsed.data.remediationSteps.length >= 1);
      assert.ok(parsed.data.citedEvidenceFields.length >= 1);
    }
    pass('Provider returns schema-valid structured JSON matching RawAIResponseSchema');

    // Schema rejection on invalid structure
    const invalidResult = RawAIResponseSchema.safeParse({
      explanation: 'Too short',
      // missing businessImpact, remediationSteps, citedEvidenceFields
    });
    assert.strictEqual(invalidResult.success, false);
    pass('RawAIResponseSchema strictly rejects incomplete or malformed outputs');
  } catch (err) {
    fail('Suite 1: Provider Abstraction & Schema Validation', err);
  }

  // -------------------------------------------------------------
  // Test Suite 2: Confidence Caveat Deterministic Templating (§2.1)
  // -------------------------------------------------------------
  console.log('\n--- Test Suite 2: Confidence Caveat Deterministic Templating (§2.1) ---');
  try {
    // DoD: Two different findings at the same confidence tier produce identically-worded caveat language
    const caveat1 = getConfidenceCaveat('INFORMATIONAL');
    const caveat2 = getConfidenceCaveat('INFORMATIONAL');
    assert.strictEqual(caveat1, caveat2);
    assert.strictEqual(
      caveat1,
      'This is an informational indicator only. No active vulnerability or malicious intent is confirmed.'
    );
    pass('DoD satisfied: Identical caveat string produced across same confidence tier');

    const confirmedCaveat = getConfidenceCaveat('CONFIRMED');
    const highCaveat = getConfidenceCaveat('HIGH');
    const mediumCaveat = getConfidenceCaveat('MEDIUM');
    const lowCaveat = getConfidenceCaveat('LOW');

    assert.notStrictEqual(confirmedCaveat, highCaveat);
    assert.notStrictEqual(highCaveat, mediumCaveat);
    assert.notStrictEqual(mediumCaveat, lowCaveat);
    assert.ok(mediumCaveat.includes('Direct exploitability has not been verified'));
    assert.ok(confirmedCaveat.includes('verified directly'));
    pass('All 5 confidence tiers map to distinct, correctly hedged deterministic templates');
  } catch (err) {
    fail('Suite 2: Confidence Caveats', err);
  }

  // -------------------------------------------------------------
  // Test Suite 3: Approved Remediation Guidance Library (§3)
  // -------------------------------------------------------------
  console.log('\n--- Test Suite 3: Approved Remediation Guidance Library (§3) ---');
  try {
    assert.ok(REMEDIATION_LIBRARY.TLS_WEAK_PROTOCOL, 'TLS_WEAK_PROTOCOL guidance exists');
    assert.ok(REMEDIATION_LIBRARY.MISSING_HSTS_HEADER, 'MISSING_HSTS_HEADER guidance exists');
    assert.ok(REMEDIATION_LIBRARY.TYPOSQUAT_DOMAIN_DETECTED, 'TYPOSQUAT_DOMAIN_DETECTED guidance exists');
    assert.ok(REMEDIATION_LIBRARY.MISSING_CSP_HEADER, 'MISSING_CSP_HEADER guidance exists');
    pass('Remediation library contains versioned playbooks for key security checks');

    // Valid step validation
    const validCheck = validateRemediationSteps('MISSING_HSTS_HEADER', [
      'Add the Strict-Transport-Security response header across all production HTTPS endpoints.',
      'Set the max-age directive to at least 31536000 seconds (1 year).',
    ]);
    assert.strictEqual(validCheck.valid, true);
    assert.strictEqual(validCheck.rejectedSteps.length, 0);
    pass('Validates and approves steps matching library guidance');

    // DoD: Attempting to have the AI layer return a remediation step whose text doesn't match is rejected
    const unapprovedStep = 'Format your hard drive and delete all database rows immediately.';
    const invalidCheck = validateRemediationSteps('MISSING_HSTS_HEADER', [
      'Add the Strict-Transport-Security response header across all production HTTPS endpoints.',
      unapprovedStep,
    ]);
    assert.strictEqual(invalidCheck.valid, false);
    assert.ok(invalidCheck.rejectedSteps.includes(unapprovedStep));
    pass('DoD satisfied: Code-level check strictly rejects novel/unapproved remediation step');
  } catch (err) {
    fail('Suite 3: Remediation Library', err);
  }

  // -------------------------------------------------------------
  // Test Suite 4: Evidence-Consistency & Anti-Hallucination Checker (§4)
  // -------------------------------------------------------------
  console.log('\n--- Test Suite 4: Evidence-Consistency & Anti-Hallucination Checker (§4) ---');
  try {
    const mockFinding = {
      _id: 'finding-test-grounding-1',
      findingCode: 'MISSING_HSTS_HEADER',
      severity: 'MEDIUM',
      confidence: 'MEDIUM',
      riskScore: 45,
      title: 'Missing HSTS Header',
      description: 'The strict transport security header was missing.',
    };
    const mockEvidence = {
      checkType: 'HTTP_HEADERS',
      targetDomain: 'app.acme.test',
      details: { missingHeaders: ['strict-transport-security'] },
    };

    // 4.1 Valid grounded response passes
    const validResponse = {
      explanation: 'The strict transport security header was missing on app.acme.test.',
      businessImpact: 'Users could theoretically be vulnerable to SSL stripping attacks on unencrypted Wi-Fi.',
      remediationSteps: [
        'Add the Strict-Transport-Security response header across all production HTTPS endpoints.',
      ],
      citedEvidenceFields: ['findingCode', 'severity', 'description'],
    };
    const validGrounding = validateEvidenceGrounding(validResponse, {
      target: mockFinding,
      evidence: mockEvidence,
    });
    assert.strictEqual(validGrounding.isValid, true);
    assert.strictEqual(validGrounding.violations.length, 0);
    pass('Valid grounded AI response passes evidence-consistency check');

    // 4.2 Deliberately corrupted case: Cites non-existent evidence field
    const corruptFieldResponse = {
      ...validResponse,
      citedEvidenceFields: ['findingCode', 'nonExistentTelemetryFieldXYZ'],
    };
    const fieldGrounding = validateEvidenceGrounding(corruptFieldResponse, {
      target: mockFinding,
      evidence: mockEvidence,
    });
    assert.strictEqual(fieldGrounding.isValid, false);
    assert.ok(fieldGrounding.violations.some((v) => v.includes('nonExistentTelemetryFieldXYZ')));
    pass('Rejects AI response citing non-existent/fabricated evidence fields');

    // 4.3 Deliberately corrupted case: Hallucinates CVE identifier
    const corruptCveResponse = {
      ...validResponse,
      explanation: 'This vulnerability corresponds to critical remote code execution CVE-2024-999999.',
    };
    const cveGrounding = validateEvidenceGrounding(corruptCveResponse, {
      target: mockFinding,
      evidence: mockEvidence,
    });
    assert.strictEqual(cveGrounding.isValid, false);
    assert.ok(cveGrounding.violations.some((v) => v.includes('CVE-2024-999999')));
    pass('Rejects AI response hallucinating ungrounded CVE identifiers');

    // 4.4 Deliberately corrupted case: Hallucinates unverified open port
    const corruptPortResponse = {
      ...validResponse,
      explanation: 'Attackers can access administrative services on port 9443.',
    };
    const portGrounding = validateEvidenceGrounding(corruptPortResponse, {
      target: mockFinding,
      evidence: mockEvidence,
    });
    assert.strictEqual(portGrounding.isValid, false);
    assert.ok(portGrounding.violations.some((v) => v.includes('9443')));
    pass('Rejects AI response hallucinating ungrounded port numbers');

    // 4.5 Deliberately corrupted case: Hallucinates unverified IP address
    const corruptIpResponse = {
      ...validResponse,
      explanation: 'C2 communication was observed contacting host 198.51.100.77.',
    };
    const ipGrounding = validateEvidenceGrounding(corruptIpResponse, {
      target: mockFinding,
      evidence: mockEvidence,
    });
    assert.strictEqual(ipGrounding.isValid, false);
    assert.ok(ipGrounding.violations.some((v) => v.includes('198.51.100.77')));
    pass('Rejects AI response hallucinating ungrounded external IP addresses');

    // 4.6 Deliberately corrupted case: Claims active breach/exploit on MEDIUM confidence finding
    const corruptExploitResponse = {
      ...validResponse,
      explanation: 'This server is actively exploited by ransomware groups.',
    };
    const exploitGrounding = validateEvidenceGrounding(corruptExploitResponse, {
      target: mockFinding,
      evidence: mockEvidence,
    });
    assert.strictEqual(exploitGrounding.isValid, false);
    assert.ok(exploitGrounding.violations.some((v) => v.includes('active exploitation')));
    pass('Rejects AI response claiming active breach or exploitation on MEDIUM-confidence finding');
  } catch (err) {
    fail('Suite 4: Grounding Checker', err);
  }

  // -------------------------------------------------------------
  // Test Suite 5: Prompt Construction & Evidence Bounding (§5)
  // -------------------------------------------------------------
  console.log('\n--- Test Suite 5: Prompt Construction & Evidence Bounding (§5) ---');
  try {
    const finding = {
      category: 'TRANSPORT_SECURITY',
      findingCode: 'TLS_WEAK_PROTOCOL',
      title: 'Insecure TLS Protocols',
      description: 'TLS 1.0 enabled.',
      severity: 'HIGH',
      confidence: 'CONFIRMED',
      riskScore: 78,
    };
    const evidence = {
      checkType: 'TLS_CERT',
      targetDomain: 'secure.acme.test',
      details: { protocols: ['TLSv1.0', 'TLSv1.2'] },
    };
    const asset = { fqdn: 'secure.acme.test', importance: 'HIGH' };

    const { systemPrompt, userPrompt } = buildFindingExplanationPrompt(finding, evidence, asset);
    assert.ok(systemPrompt.includes('Grounded AI Security Analyst'));
    assert.ok(systemPrompt.includes('NON-NEGOTIABLE GROUNDING RULES'));
    assert.ok(userPrompt.includes('TLS_WEAK_PROTOCOL'));
    assert.ok(userPrompt.includes('secure.acme.test'));
    assert.ok(userPrompt.includes('Approved Remediation Steps for TLS_WEAK_PROTOCOL'));
    pass('Constructs evidence-bounded prompt with strict grounding constraints');

    const threat = {
      indicator: 'acrne.com',
      relatedRootDomain: 'acme.com',
      source: 'TYPOSQUAT_PERMUTATION',
      confidence: 'HIGH',
      corroborationScore: 70,
      corroborationFactors: { isResolving: true, hasMxRecords: true },
    };
    const threatPrompt = buildThreatExplanationPrompt(threat, null);
    assert.ok(threatPrompt.userPrompt.includes('acrne.com'));
    assert.ok(threatPrompt.userPrompt.includes('hasMxRecords'));
    pass('Constructs threat prompt incorporating corroboration factors');
  } catch (err) {
    fail('Suite 5: Prompt Construction', err);
  }

  // -------------------------------------------------------------
  // Test Suite 6: Failure Handling & Deterministic Fallback (§6)
  // -------------------------------------------------------------
  console.log('\n--- Test Suite 6: Failure Handling & Deterministic Fallback (§6) ---');
  try {
    const finding = {
      findingCode: 'TLS_CERT_EXPIRED',
      title: 'Expired Certificate',
      severity: 'HIGH',
      confidence: 'CONFIRMED',
    };
    const fallback = generateFindingFallback(finding, { targetDomain: 'expired.acme.test' });
    assert.strictEqual(fallback.isFallback, true);
    assert.strictEqual(fallback.isAIGenerated, false);
    assert.ok(fallback.explanation.includes('expired'));
    assert.ok(fallback.remediationSteps.length > 0);
    assert.strictEqual(fallback.confidenceCaveat, getConfidenceCaveat('CONFIRMED'));
    pass('Generates high-quality deterministic fallback on finding');

    const threat = {
      indicator: 'dormant-acme.test',
      relatedRootDomain: 'acme.test',
      corroborationScore: 10,
      confidence: 'INFORMATIONAL',
      corroborationFactors: { isResolving: false },
    };
    const threatFallback = generateThreatFallback(threat);
    assert.strictEqual(threatFallback.isFallback, true);
    assert.ok(threatFallback.explanation.includes('dormant'));
    assert.strictEqual(threatFallback.confidenceCaveat, getConfidenceCaveat('INFORMATIONAL'));
    pass('Generates accurate fallback for dormant brand threats');
  } catch (err) {
    fail('Suite 6: Failure Handling & Fallback', err);
  }

  // -------------------------------------------------------------
  // Test Suite 7: Findings Explanation & Caching API (§7)
  // -------------------------------------------------------------
  console.log('\n--- Test Suite 7: Findings Explanation & Caching API (§7) ---');
  try {
    const orgId = `org-ai-test-${Date.now()}`;
    const findingId = `finding-ai-test-${Date.now()}`;
    const evidenceId = `evidence-ai-test-${Date.now()}`;
    const assetId = `asset-ai-test-${Date.now()}`;

    memoryStore.assets.set(assetId, {
      _id: assetId,
      organizationId: orgId,
      fqdn: 'api.acme.test',
      importance: 'CRITICAL',
    });

    memoryStore.evidence.set(evidenceId, {
      _id: evidenceId,
      organizationId: orgId,
      checkType: 'HTTP_HEADERS',
      targetDomain: 'api.acme.test',
      contentHash: 'mock-hash-12345',
      details: { missingHeaders: ['strict-transport-security'] },
    });

    memoryStore.findings.set(findingId, {
      _id: findingId,
      organizationId: orgId,
      assetId,
      evidenceId,
      findingCode: 'MISSING_HSTS_HEADER',
      title: 'Missing HSTS Header',
      description: 'HSTS is not configured on api.acme.test',
      severity: 'MEDIUM',
      confidence: 'HIGH',
      riskScore: 65,
      status: 'OPEN',
      updatedAt: new Date(),
    });

    // 7.1 First call: Fresh generation
    mock.resetHandler();
    const result1 = await explainFinding(findingId, orgId);
    assert.ok(result1);
    assert.strictEqual(result1.isAIGenerated, true);
    assert.strictEqual(result1.isFallback, false);
    assert.strictEqual(result1.confidenceCaveat, getConfidenceCaveat('HIGH'));
    pass('explainFinding generates grounded explanation via provider');

    // 7.2 Second call: Cache hit
    const result2 = await explainFinding(findingId, orgId);
    assert.ok(result2);
    assert.strictEqual(result2.cacheHit, true);
    pass('explainFinding returns cached explanation on repeated query');

    // 7.3 Cache invalidation when severity/status changes
    const findingRecord = memoryStore.findings.get(findingId);
    findingRecord.severity = 'CRITICAL';
    findingRecord.riskScore = 95;

    const result3 = await explainFinding(findingId, orgId);
    assert.ok(result3);
    assert.strictEqual(result3.cacheHit, undefined); // fresh generation
    pass('Cache invalidates and regenerates explanation when finding severity changes');

    // 7.4 Graceful fallback when provider times out
    mock.setHandler(async () => {
      throw new Error('Upstream LLM timeout 10000ms exceeded');
    });

    const timeoutFindingId = `finding-timeout-${Date.now()}`;
    memoryStore.findings.set(timeoutFindingId, {
      _id: timeoutFindingId,
      organizationId: orgId,
      findingCode: 'TLS_WEAK_PROTOCOL',
      title: 'Weak Protocol',
      severity: 'HIGH',
      confidence: 'HIGH',
      riskScore: 75,
      status: 'OPEN',
    });

    const fallbackResult = await explainFinding(timeoutFindingId, orgId);
    assert.ok(fallbackResult);
    assert.strictEqual(fallbackResult.isFallback, true);
    assert.strictEqual(fallbackResult.isAIGenerated, false);
    assert.ok(fallbackResult.explanation.length > 0);
    pass('Gracefully returns deterministic fallback when LLM call errors or times out');

    // 7.5 Graceful fallback when grounding check repeatedly fails
    mock.setHandler(async () => {
      return {
        explanation: 'Hallucinated remote exploit CVE-2029-0001 with active breach',
        businessImpact: 'Critical server takeover on port 9999',
        remediationSteps: ['Unapproved random step'],
        citedEvidenceFields: ['fabricatedField'],
      };
    });

    const rejectedFindingId = `finding-rejected-${Date.now()}`;
    memoryStore.findings.set(rejectedFindingId, {
      _id: rejectedFindingId,
      organizationId: orgId,
      findingCode: 'MISSING_HSTS_HEADER',
      title: 'Missing HSTS',
      severity: 'MEDIUM',
      confidence: 'MEDIUM',
      riskScore: 50,
      status: 'OPEN',
    });

    const rejectedResult = await explainFinding(rejectedFindingId, orgId);
    assert.ok(rejectedResult);
    assert.strictEqual(rejectedResult.isFallback, true); // Fell back after retries!
    assert.strictEqual(rejectedResult.isAIGenerated, false);
    pass('Repeated grounding validation failure gracefully falls back to deterministic template');

    mock.resetHandler();
  } catch (err) {
    fail('Suite 7: Finding Explanation API', err);
  }

  // -------------------------------------------------------------
  // Test Suite 8: Threats Explanation API (§7)
  // -------------------------------------------------------------
  console.log('\n--- Test Suite 8: Threats Explanation API (§7) ---');
  try {
    const orgId = `org-threat-ai-${Date.now()}`;
    const threatId = `threat-ai-${Date.now()}`;

    memoryStore.threats.set(threatId, {
      _id: threatId,
      organizationId: orgId,
      indicator: 'acme-login-portal.com',
      relatedRootDomain: 'acme.com',
      source: 'TYPOSQUAT_PERMUTATION',
      confidence: 'HIGH',
      corroborationScore: 75,
      corroborationFactors: { isResolving: true, hasMxRecords: true },
      status: 'OPEN',
    });

    mock.resetHandler();
    const threatExplain = await explainThreat(threatId, orgId);
    assert.ok(threatExplain);
    assert.strictEqual(threatExplain.isAIGenerated, true);
    assert.strictEqual(threatExplain.confidenceCaveat, getConfidenceCaveat('HIGH'));
    pass('explainThreat generates corroborated explanation for typosquat threat');

    // Repeated call hits cache
    const cachedThreat = await explainThreat(threatId, orgId);
    assert.strictEqual(cachedThreat?.cacheHit, true);
    pass('explainThreat caches and retrieves explanation');
  } catch (err) {
    fail('Suite 8: Threat Explanation API', err);
  }

  // -------------------------------------------------------------
  // Test Suite 9: Executive Summary Generator (§8)
  // -------------------------------------------------------------
  console.log('\n--- Test Suite 9: Executive Summary Generator (§8) ---');
  try {
    const orgId = `org-exec-${Date.now()}`;
    memoryStore.organizations.set(orgId, {
      _id: orgId,
      name: 'Globex Security Ltd',
    });

    // Populate mix of CONFIRMED, HIGH, MEDIUM, and LOW items
    memoryStore.findings.set(`f-conf-${Date.now()}`, {
      _id: `f-conf-${Date.now()}`,
      organizationId: orgId,
      title: 'Confirmed Expired Certificate',
      severity: 'CRITICAL',
      confidence: 'CONFIRMED',
      status: 'OPEN',
    });
    memoryStore.findings.set(`f-high-${Date.now()}`, {
      _id: `f-high-${Date.now()}`,
      title: 'High Severity Protocol',
      organizationId: orgId,
      severity: 'HIGH',
      confidence: 'HIGH',
      status: 'OPEN',
    });
    // This LOW finding must be filtered out
    memoryStore.findings.set(`f-low-${Date.now()}`, {
      _id: `f-low-${Date.now()}`,
      title: 'Low Informational Header',
      organizationId: orgId,
      severity: 'LOW',
      confidence: 'LOW',
      status: 'OPEN',
    });

    const summary = await generateExecutiveSummary(orgId);
    assert.ok(summary);
    assert.ok(summary.executiveSummary.length > 20);
    assert.ok(summary.overallPosture);
    assert.strictEqual(summary.totalConfirmedFindings, 2); // only CONFIRMED + HIGH
    pass('Executive summary strictly aggregates only CONFIRMED and HIGH confidence items');
  } catch (err) {
    fail('Suite 9: Executive Summary', err);
  }

  // -------------------------------------------------------------
  // Test Suite 10: AuditLog Recording & HTTP Route Verification
  // -------------------------------------------------------------
  console.log('\n--- Test Suite 10: AuditLog Recording & HTTP Route Verification ---');
  try {
    const orgId = `org-routes-${Date.now()}`;
    const token = createSessionToken({
      userId: 'user-audit-test',
      email: 'secops@audit.test',
      organizationId: orgId,
      role: 'ADMIN',
    });

    const findingId = `finding-http-${Date.now()}`;
    memoryStore.findings.set(findingId, {
      _id: findingId,
      organizationId: orgId,
      findingCode: 'MISSING_HSTS_HEADER',
      title: 'Missing HSTS',
      severity: 'HIGH',
      confidence: 'HIGH',
      status: 'OPEN',
    });

    // Route: GET /api/findings/:id/explain
    const req = new NextRequest(`http://localhost:3000/api/findings/${findingId}/explain`, {
      headers: { Cookie: `pliora_session=${token}` },
    });
    const res = await getFindingExplain(req, { params: Promise.resolve({ id: findingId }) });
    assert.strictEqual(res.status, 200);
    const json = await res.json();
    assert.strictEqual(json.success, true);
    assert.ok(json.data.explanation);
    pass('GET /api/findings/:id/explain returns 200 with valid explanation envelope');

    // Cross-tenant protection: Attempting to access from different org returns 404
    const diffOrgToken = createSessionToken({
      userId: 'user-diff-tenant',
      email: 'attacker@other.test',
      organizationId: 'other-org-999',
      role: 'ADMIN',
    });
    const crossReq = new NextRequest(`http://localhost:3000/api/findings/${findingId}/explain`, {
      headers: { Cookie: `pliora_session=${diffOrgToken}` },
    });
    const crossRes = await getFindingExplain(crossReq, { params: Promise.resolve({ id: findingId }) });
    assert.strictEqual(crossRes.status, 404);
    pass('Cross-tenant explanation request returns 404 (anti-enumeration defense)');

    // Route: GET /api/reports/executive-summary
    const execReq = new NextRequest('http://localhost:3000/api/reports/executive-summary', {
      headers: { Cookie: `pliora_session=${token}` },
    });
    const execRes = await getExecutiveSummary(execReq);
    assert.strictEqual(execRes.status, 200);
    const execJson = await execRes.json();
    assert.strictEqual(execJson.success, true);
    assert.ok(execJson.data.executiveSummary);
    pass('GET /api/reports/executive-summary returns 200 with structured report');

    // Verify AuditLog entries exist
    const hasGenLog = memoryStore.auditLogs.some(
      (log) => log.action === 'AI_EXPLANATION_GENERATED' && log.organizationId === orgId
    );
    assert.strictEqual(hasGenLog, true);
    pass('Verified AuditLog records AI_EXPLANATION_GENERATED on success');

    const hasRejLog = memoryStore.auditLogs.some((log) => log.action === 'AI_GROUNDING_REJECTED');
    assert.strictEqual(hasRejLog, true);
    pass('Verified AuditLog records AI_GROUNDING_REJECTED on grounding violation');
  } catch (err) {
    fail('Suite 10: Audit Logs & HTTP Routes', err);
  }

  // -------------------------------------------------------------
  // Summary
  // -------------------------------------------------------------
  console.log('\n=============================================');
  console.log(` Option 7 Test Summary: ${passed} Passed, ${failed} Failed`);
  console.log('=============================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
