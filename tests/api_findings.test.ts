import { NextRequest } from 'next/server';
import { GET as getFindings } from '../src/app/api/findings/route';
import { GET as getFindingById, PATCH as patchFindingById } from '../src/app/api/findings/[id]/route';
import { PATCH as patchAssetById } from '../src/app/api/assets/[id]/route';
import { GET as getRiskScore } from '../src/app/api/risk-score/route';
import { GET as getRiskScoreHistory } from '../src/app/api/risk-score/history/route';
import { memoryStore } from '../src/lib/store';
import { createSessionToken } from '../src/lib/auth';
import { processScanJob } from '../src/workers/scanProcessor';
import { computeFindingDedupHash } from '../src/lib/plugins/findings';
import { pluginRegistry } from '../src/lib/plugins/registry';
import { FindingSeverity, FindingStatus } from '../src/types';

let passed = 0;
let failed = 0;

function assert(condition: boolean, msg: string) {
  if (condition) {
    console.log(`  ✅ PASS: ${msg}`);
    passed++;
  } else {
    console.error(`  ❌ FAIL: ${msg}`);
    failed++;
  }
}

function createMockRequest(url: string, options: { method?: string; body?: any; token?: string } = {}): NextRequest {
  const headers = new Headers();
  headers.set('host', 'localhost:3000');
  if (options.token) {
    headers.set('Cookie', `pliora_session=${options.token}`);
    headers.set('Authorization', `Bearer ${options.token}`);
  }
  if (options.body) {
    headers.set('Content-Type', 'application/json');
  }

  return new NextRequest(url, {
    method: options.method || 'GET',
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
}

async function runFindingsApiTests() {
  console.log('🛡️ Running Findings API & Triage State Machine Tests...\n');

  // ==========================================
  // Setup Seed Data: Org A and Org B
  // ==========================================
  const orgAId = 'org-triage-test-a';
  const orgBId = 'org-triage-test-b';

  const userAId = 'user-triage-admin-a';
  const userViewerAId = 'user-triage-viewer-a';
  const userBId = 'user-triage-admin-b';

  memoryStore.organizations.set(orgAId, {
    _id: orgAId,
    name: 'Org A Security',
    slug: 'org-a',
    plan: 'BUSINESS',
    scanQuotas: { maxMonitoredDomains: 5, dailyScanLimit: 20, concurrentScans: 3 },
  });

  memoryStore.organizations.set(orgBId, {
    _id: orgBId,
    name: 'Org B Security',
    slug: 'org-b',
    plan: 'FREE',
    scanQuotas: { maxMonitoredDomains: 2, dailyScanLimit: 5, concurrentScans: 1 },
  });

  memoryStore.users.set(userAId, {
    _id: userAId,
    email: 'admin@orga.test',
    activeOrganizationId: orgAId,
    organizationMemberships: [{ organizationId: orgAId, role: 'ADMIN', joinedAt: new Date() }],
  });

  memoryStore.users.set(userViewerAId, {
    _id: userViewerAId,
    email: 'viewer@orga.test',
    activeOrganizationId: orgAId,
    organizationMemberships: [{ organizationId: orgAId, role: 'VIEWER', joinedAt: new Date() }],
  });

  memoryStore.users.set(userBId, {
    _id: userBId,
    email: 'admin@orgb.test',
    activeOrganizationId: orgBId,
    organizationMemberships: [{ organizationId: orgBId, role: 'OWNER', joinedAt: new Date() }],
  });

  const tokenAdminA = createSessionToken({
    userId: userAId,
    email: 'admin@orga.test',
    organizationId: orgAId,
    role: 'ADMIN',
  });

  const tokenViewerA = createSessionToken({
    userId: userViewerAId,
    email: 'viewer@orga.test',
    organizationId: orgAId,
    role: 'VIEWER',
  });

  const tokenAdminB = createSessionToken({
    userId: userBId,
    email: 'admin@orgb.test',
    organizationId: orgBId,
    role: 'OWNER',
  });

  // Seed assets
  const assetA = {
    _id: 'asset-a-01',
    organizationId: orgAId,
    fqdn: 'api.orga.test',
    rootDomain: 'orga.test',
    type: 'SUBDOMAIN',
    importance: 'HIGH',
    verificationStatus: 'VERIFIED',
    ipAddresses: ['93.184.216.34'],
    tags: ['production'],
  };
  memoryStore.assets.set(assetA._id, assetA);

  const assetB = {
    _id: 'asset-b-01',
    organizationId: orgBId,
    fqdn: 'api.orgb.test',
    rootDomain: 'orgb.test',
    type: 'SUBDOMAIN',
    importance: 'NORMAL',
    verificationStatus: 'VERIFIED',
    ipAddresses: ['93.184.216.35'],
    tags: ['production'],
  };
  memoryStore.assets.set(assetB._id, assetB);

  // Seed Evidence
  const evidenceA = {
    _id: 'ev-a-01',
    organizationId: orgAId,
    assetId: assetA._id,
    scanId: 'scan-a-01',
    checkType: 'TLS_HANDSHAKE',
    rawObservation: { cipher: 'RC4-SHA', protocol: 'TLSv1.0' },
    contentHash: 'hash-evidence-a-01',
    observedAt: new Date(),
  };
  memoryStore.evidence.set(evidenceA._id, evidenceA);

  // Seed Findings for Org A
  const findingA1 = {
    _id: 'finding-a-01',
    organizationId: orgAId,
    assetId: assetA._id,
    evidenceId: evidenceA._id,
    category: 'TRANSPORT_SECURITY',
    findingCode: 'TLS-OBSOLETE-PROTOCOL',
    title: 'Obsolete TLS 1.0 Enabled',
    description: 'Endpoint supports deprecated TLS 1.0 protocol.',
    severity: 'HIGH' as FindingSeverity,
    confidence: 'CONFIRMED',
    riskScore: 75,
    status: 'OPEN' as FindingStatus,
    dedupHash: 'dedup-a-01',
    firstSeen: new Date(),
    lastSeen: new Date(),
    createdAt: new Date(),
  };

  const findingA2 = {
    _id: 'finding-a-02',
    organizationId: orgAId,
    assetId: assetA._id,
    evidenceId: evidenceA._id,
    category: 'HTTP_SECURITY_HEADERS',
    findingCode: 'SEC-HEADER-CSP-MISSING',
    title: 'Content-Security-Policy Missing',
    description: 'Header missing on endpoint.',
    severity: 'MEDIUM' as FindingSeverity,
    confidence: 'CONFIRMED',
    riskScore: 45,
    status: 'OPEN' as FindingStatus,
    dedupHash: 'dedup-a-02',
    firstSeen: new Date(),
    lastSeen: new Date(),
    createdAt: new Date(),
  };

  const findingB1 = {
    _id: 'finding-b-01',
    organizationId: orgBId,
    assetId: assetB._id,
    evidenceId: 'ev-b-01',
    category: 'TECH_VERSION',
    findingCode: 'TECH-SERVER-BANNER',
    title: 'Server Banner Disclosed',
    description: 'nginx banner.',
    severity: 'LOW' as FindingSeverity,
    confidence: 'MEDIUM',
    riskScore: 20,
    status: 'OPEN' as FindingStatus,
    dedupHash: 'dedup-b-01',
    firstSeen: new Date(),
    lastSeen: new Date(),
    createdAt: new Date(),
  };

  memoryStore.findings.set(findingA1._id, findingA1);
  memoryStore.findings.set(findingA2._id, findingA2);
  memoryStore.findings.set(findingB1._id, findingB1);

  // ==========================================
  // Test Group 1: Multi-Tenant Scoping
  // ==========================================
  console.log('Test Group 1: Multi-Tenant Scoping & Filtering');

  const reqListA = createMockRequest('http://localhost:3000/api/findings', { token: tokenAdminA });
  const resListA = await getFindings(reqListA);
  const dataListA = await resListA.json();

  assert(resListA.status === 200, 'GET /api/findings returns 200 OK');
  assert(dataListA.success === true, 'Response indicates success');
  assert(dataListA.data.length === 2, `Org A receives exactly 2 findings (got: ${dataListA.data.length})`);
  assert(
    dataListA.data.every((f: any) => f.organizationId === orgAId),
    'All returned findings belong exclusively to Org A'
  );
  assert(
    !dataListA.data.some((f: any) => f._id === findingB1._id),
    'Org A never sees Org B finding'
  );

  // Test filter by severity
  const reqFilterHigh = createMockRequest('http://localhost:3000/api/findings?severity=HIGH', { token: tokenAdminA });
  const resFilterHigh = await getFindings(reqFilterHigh);
  const dataFilterHigh = await resFilterHigh.json();
  assert(dataFilterHigh.data.length === 1, 'Filtering by severity=HIGH returns 1 finding');
  assert(dataFilterHigh.data[0].findingCode === 'TLS-OBSOLETE-PROTOCOL', 'Returns expected HIGH finding');

  // ==========================================
  // Test Group 2: Detail View with Inline Evidence & 404 Guard
  // ==========================================
  console.log('\nTest Group 2: Detail View & Cross-Tenant 404 Guard');

  const reqDetailA = createMockRequest(`http://localhost:3000/api/findings/${findingA1._id}`, { token: tokenAdminA });
  const resDetailA = await getFindingById(reqDetailA, { params: Promise.resolve({ id: findingA1._id }) });
  const dataDetailA = await resDetailA.json();

  assert(resDetailA.status === 200, 'GET /api/findings/:id returns 200 OK');
  assert(dataDetailA.data._id === findingA1._id, 'Returns requested finding');
  assert(dataDetailA.data.evidence !== null, 'Evidence is embedded inline');
  assert(dataDetailA.data.evidence.checkType === 'TLS_HANDSHAKE', 'Evidence contains checkType');
  assert(dataDetailA.data.evidence.rawObservation.cipher === 'RC4-SHA', 'Evidence contains raw observations');

  // Cross-tenant lookup must return 404 (NOT 403) to prevent existence leaking
  const reqCrossTenant = createMockRequest(`http://localhost:3000/api/findings/${findingB1._id}`, { token: tokenAdminA });
  const resCrossTenant = await getFindingById(reqCrossTenant, { params: Promise.resolve({ id: findingB1._id }) });
  assert(
    resCrossTenant.status === 404,
    `Cross-tenant access to Org B finding returns 404 Not Found (got: ${resCrossTenant.status})`
  );

  // ==========================================
  // Test Group 3: Status Transition State Machine
  // ==========================================
  console.log('\nTest Group 3: Status Transition State Machine & Auditing');

  // 1. Transition OPEN -> ACCEPTED_RISK
  const reqAcceptRisk = createMockRequest(`http://localhost:3000/api/findings/${findingA1._id}`, {
    method: 'PATCH',
    token: tokenAdminA,
    body: { status: 'ACCEPTED_RISK', notes: 'Legacy system dependency approved by SecOps', reason: 'Business trade-off' },
  });
  const resAcceptRisk = await patchFindingById(reqAcceptRisk, { params: Promise.resolve({ id: findingA1._id }) });
  const dataAcceptRisk = await resAcceptRisk.json();

  assert(resAcceptRisk.status === 200, 'PATCH /api/findings/:id OPEN -> ACCEPTED_RISK returns 200 OK');
  assert(dataAcceptRisk.data.status === 'ACCEPTED_RISK', 'Finding status transitioned to ACCEPTED_RISK');
  assert(typeof dataAcceptRisk.orgRiskScore.score === 'number', 'Returns updated inline org risk score');

  // Verify AuditLog written
  const auditEntry = memoryStore.auditLogs.find(
    (a) => a.action === 'FINDING_STATUS_CHANGED' && a.objectId === findingA1._id
  );
  assert(!!auditEntry, 'Generates AuditLog record with action FINDING_STATUS_CHANGED');
  assert(auditEntry.details.previousStatus === 'OPEN', 'AuditLog records previousStatus: OPEN');
  assert(auditEntry.details.newStatus === 'ACCEPTED_RISK', 'AuditLog records newStatus: ACCEPTED_RISK');

  // Verify CalibrationFeedback written
  const feedbackEntry = memoryStore.calibrationFeedback.find(
    (f) => f.findingId === findingA1._id && f.action === 'ACCEPTED_RISK'
  );
  assert(!!feedbackEntry, 'Generates CalibrationFeedback record with action ACCEPTED_RISK');
  assert(feedbackEntry.severityAtTriage === 'HIGH', 'Feedback captures severity at triage (HIGH)');

  // 2. Invalid Transition: ACCEPTED_RISK -> FALSE_POSITIVE
  const reqInvalidTrans = createMockRequest(`http://localhost:3000/api/findings/${findingA1._id}`, {
    method: 'PATCH',
    token: tokenAdminA,
    body: { status: 'FALSE_POSITIVE' },
  });
  const resInvalidTrans = await patchFindingById(reqInvalidTrans, { params: Promise.resolve({ id: findingA1._id }) });
  assert(
    resInvalidTrans.status === 400,
    `State machine rejects invalid transition ACCEPTED_RISK -> FALSE_POSITIVE with 400 Bad Request (got: ${resInvalidTrans.status})`
  );

  // 3. Transition ACCEPTED_RISK -> RESOLVED
  const reqResolve = createMockRequest(`http://localhost:3000/api/findings/${findingA1._id}`, {
    method: 'PATCH',
    token: tokenAdminA,
    body: { status: 'RESOLVED', notes: 'Patch deployed.' },
  });
  const resResolve = await patchFindingById(reqResolve, { params: Promise.resolve({ id: findingA1._id }) });
  assert(resResolve.status === 200, 'Transition ACCEPTED_RISK -> RESOLVED returns 200 OK');

  // 4. Invalid Transition: RESOLVED -> ACCEPTED_RISK
  const reqInvalidFromResolved = createMockRequest(`http://localhost:3000/api/findings/${findingA1._id}`, {
    method: 'PATCH',
    token: tokenAdminA,
    body: { status: 'ACCEPTED_RISK' },
  });
  const resInvalidFromResolved = await patchFindingById(reqInvalidFromResolved, { params: Promise.resolve({ id: findingA1._id }) });
  assert(
    resInvalidFromResolved.status === 400,
    `State machine rejects invalid transition RESOLVED -> ACCEPTED_RISK with 400 Bad Request (got: ${resInvalidFromResolved.status})`
  );

  // ==========================================
  // Test Group 4: Role-Based Authorization Checks
  // ==========================================
  console.log('\nTest Group 4: Role-Based Authorization Checks');

  // Viewer attempt to patch finding triage status must be denied with 403
  const reqViewerPatch = createMockRequest(`http://localhost:3000/api/findings/${findingA2._id}`, {
    method: 'PATCH',
    token: tokenViewerA,
    body: { status: 'RESOLVED' },
  });
  const resViewerPatch = await patchFindingById(reqViewerPatch, { params: Promise.resolve({ id: findingA2._id }) });
  const dataViewerPatch = await resViewerPatch.json();

  assert(
    resViewerPatch.status === 403,
    `Viewer role is denied mutation with 403 Forbidden (got: ${resViewerPatch.status})`
  );
  assert(dataViewerPatch.error.code === 'INSUFFICIENT_PERMISSIONS', 'Error code is INSUFFICIENT_PERMISSIONS');

  // Viewer CAN read findings
  const reqViewerGet = createMockRequest('http://localhost:3000/api/findings', { token: tokenViewerA });
  const resViewerGet = await getFindings(reqViewerGet);
  assert(resViewerGet.status === 200, 'Viewer role is permitted to read findings (200 OK)');

  // ==========================================
  // Test Group 5: Re-Detection & Auto-Reopen Behavior
  // ==========================================
  console.log('\nTest Group 5: Re-Detection & Auto-Reopen Invariants');

  // Case A: findingA1 is currently RESOLVED.
  // In scanProcessor Stage 4, if a scan re-detects findingA1 (same dedupHash):
  // It should automatically re-open it to OPEN and generate a FINDING_AUTO_REOPENED audit entry.

  const autoReopenAsset = {
    _id: 'asset-reopen-01',
    organizationId: orgAId,
    fqdn: 'dns.google',
    rootDomain: 'google',
    type: 'ROOT_DOMAIN' as const,
    importance: 'CRITICAL' as const,
    verificationStatus: 'VERIFIED' as const,
    ipAddresses: ['8.8.8.8'],
    tags: ['production'],
  };
  memoryStore.assets.set(autoReopenAsset._id, autoReopenAsset);

  // Register a deterministic plugin for re-detection testing
  const deterministicPlugin = {
    id: 'reopen-test-plugin',
    name: 'Reopen Test Plugin',
    category: 'EXPOSED_SERVICES' as const,
    defaultConfidence: 'CONFIRMED' as const,
    appliesTo: () => true,
    run: async () => ({
      status: 'COMPLETED' as const,
      evidence: [
        {
          checkType: 'SERVICE_BANNER' as const,
          rawObservation: { port: 8080, banner: 'test' },
        },
      ],
      findings: [
        {
          category: 'EXPOSED_SERVICES' as const,
          findingCode: 'TEST-REOPEN-VULN',
          title: 'Deterministic Test Vuln',
          description: 'Test vuln for reopen verification.',
          severity: 'HIGH' as const,
          confidence: 'CONFIRMED' as const,
        },
        {
          category: 'EXPOSED_SERVICES' as const,
          findingCode: 'TEST-ACCEPTED-VULN',
          title: 'Deterministic Accepted Vuln',
          description: 'Test vuln for accepted risk verification.',
          severity: 'MEDIUM' as const,
          confidence: 'CONFIRMED' as const,
        },
      ],
      durationMs: 5,
    }),
  };
  pluginRegistry.register(deterministicPlugin);

  const testDedupHash = computeFindingDedupHash(orgAId, autoReopenAsset._id, 'TEST-REOPEN-VULN');
  const storeKey = `${orgAId}:${testDedupHash}`;

  // Seed existing RESOLVED finding that will be re-detected on scan
  const pastDate = new Date(Date.now() - 86400000);
  const resolvedFinding = {
    _id: 'finding-resolved-01',
    organizationId: orgAId,
    assetId: autoReopenAsset._id,
    evidenceId: 'ev-test-01',
    category: 'EXPOSED_SERVICES',
    findingCode: 'TEST-REOPEN-VULN',
    title: 'Deterministic Test Vuln',
    description: 'Test vuln for reopen verification.',
    severity: 'HIGH' as FindingSeverity,
    confidence: 'CONFIRMED',
    riskScore: 70,
    status: 'RESOLVED' as FindingStatus,
    dedupHash: testDedupHash,
    firstSeen: pastDate,
    lastSeen: pastDate,
    createdAt: pastDate,
  };
  memoryStore.findings.set(storeKey, resolvedFinding);

  // Seed existing ACCEPTED_RISK finding that will also be re-detected
  const acceptedDedupHash = computeFindingDedupHash(orgAId, autoReopenAsset._id, 'TEST-ACCEPTED-VULN');
  const acceptedStoreKey = `${orgAId}:${acceptedDedupHash}`;
  const acceptedFinding = {
    _id: 'finding-accepted-01',
    organizationId: orgAId,
    assetId: autoReopenAsset._id,
    evidenceId: 'ev-test-02',
    category: 'EXPOSED_SERVICES',
    findingCode: 'TEST-ACCEPTED-VULN',
    title: 'Deterministic Accepted Vuln',
    description: 'Test vuln for accepted risk verification.',
    severity: 'MEDIUM' as FindingSeverity,
    confidence: 'CONFIRMED',
    riskScore: 40,
    status: 'ACCEPTED_RISK' as FindingStatus,
    dedupHash: acceptedDedupHash,
    firstSeen: pastDate,
    lastSeen: pastDate,
    createdAt: pastDate,
  };
  memoryStore.findings.set(acceptedStoreKey, acceptedFinding);

  // Run scan on autoReopenAsset
  const scanDoc = {
    _id: 'scan-reopen-01',
    organizationId: orgAId,
    assetId: autoReopenAsset._id,
    target: autoReopenAsset.fqdn,
    type: 'EXPOSURE',
    status: 'QUEUED',
    progress: 0,
    counters: { checksCompleted: 0, findingsCreated: 0 },
    pluginRuns: [],
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  memoryStore.scans.set(scanDoc._id, scanDoc);

  // We invoke processScanJob
  await processScanJob({
    scanId: scanDoc._id,
    organizationId: orgAId,
    assetId: autoReopenAsset._id,
    scanType: 'EXPOSURE',
  });

  pluginRegistry.unregister('reopen-test-plugin');

  // Check auto-reopened finding status
  const reopenedFinding = memoryStore.findings.get(storeKey);
  assert(reopenedFinding.status === 'OPEN', 'RESOLVED finding is automatically reopened to OPEN upon re-detection');
  assert(new Date(reopenedFinding.lastSeen).getTime() > pastDate.getTime(), 'Reopened finding has refreshed lastSeen timestamp');

  // Verify AuditLog and Feedback created for auto-reopen
  const reopenAudit = memoryStore.auditLogs.find(
    (a) => a.action === 'FINDING_AUTO_REOPENED' && a.objectId === resolvedFinding._id
  );
  assert(!!reopenAudit, 'Generates FINDING_AUTO_REOPENED AuditLog record');

  const reopenFeedback = memoryStore.calibrationFeedback.find(
    (f) => f.findingId === resolvedFinding._id && f.action === 'REOPENED'
  );
  assert(!!reopenFeedback, 'Generates CalibrationFeedback record with action REOPENED');

  // Case B: An ACCEPTED_RISK finding must NOT be auto-reopened
  const stillAcceptedFinding = memoryStore.findings.get(acceptedStoreKey);
  assert(stillAcceptedFinding.status === 'ACCEPTED_RISK', 'ACCEPTED_RISK finding preserves ACCEPTED_RISK status on re-detection');
  assert(new Date(stillAcceptedFinding.lastSeen).getTime() > pastDate.getTime(), 'ACCEPTED_RISK finding has refreshed lastSeen timestamp');

  // ==========================================
  // Test Group 6: Risk Score & History Endpoints
  // ==========================================
  console.log('\nTest Group 6: Risk Score Endpoints (/api/risk-score & /history)');

  const reqScore = createMockRequest('http://localhost:3000/api/risk-score', { token: tokenAdminA });
  const resScore = await getRiskScore(reqScore);
  const dataScore = await resScore.json();

  assert(resScore.status === 200, 'GET /api/risk-score returns 200 OK');
  assert(typeof dataScore.data.score === 'number', 'Returns score number');
  assert(typeof dataScore.data.securityPosture === 'number', 'Returns securityPosture number');
  assert(['A', 'B', 'C', 'D', 'F'].includes(dataScore.data.grade), `Returns valid letter grade (${dataScore.data.grade})`);
  assert(dataScore.data.findingCounts !== undefined, 'Returns findingCounts breakdown');

  const reqHistory = createMockRequest('http://localhost:3000/api/risk-score/history?limit=10', { token: tokenAdminA });
  const resHistory = await getRiskScoreHistory(reqHistory);
  const dataHistory = await resHistory.json();

  assert(resHistory.status === 200, 'GET /api/risk-score/history returns 200 OK');
  assert(Array.isArray(dataHistory.data), 'History returns an array of snapshots');
  assert(dataHistory.data.length > 0, `History contains snapshots (found: ${dataHistory.data.length})`);

  // ==========================================
  // Test Group 7: Asset Importance Mutation
  // ==========================================
  console.log('\nTest Group 7: Asset Importance Mutation (/api/assets/:id)');

  const reqPatchAsset = createMockRequest(`http://localhost:3000/api/assets/${assetA._id}`, {
    method: 'PATCH',
    token: tokenAdminA,
    body: { importance: 'CRITICAL', tags: ['production', 'tier-1-crown-jewel'] },
  });
  const resPatchAsset = await patchAssetById(reqPatchAsset, { params: Promise.resolve({ id: assetA._id }) });
  const dataPatchAsset = await resPatchAsset.json();

  assert(resPatchAsset.status === 200, 'PATCH /api/assets/:id returns 200 OK');
  assert(dataPatchAsset.data.importance === 'CRITICAL', 'Asset importance updated to CRITICAL');
  assert(dataPatchAsset.data.tags.includes('tier-1-crown-jewel'), 'Asset tags updated');

  console.log(`\n========================================`);
  console.log(`Findings API Test Results: ${passed} Passed, ${failed} Failed`);
  console.log(`========================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runFindingsApiTests().catch((err) => {
  console.error('Fatal API test error:', err);
  process.exit(1);
});
