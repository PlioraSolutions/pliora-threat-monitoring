import { NextRequest } from 'next/server';
import { memoryStore } from '../src/lib/store';
import { createSessionToken } from '../src/lib/auth';
import {
  shouldAlertOnFinding,
  shouldAlertOnAssetDiscovery,
  computeAlertDedupKey,
  isAlertSuppressed,
  ALERT_RISK_SCORE_THRESHOLD,
  DEFAULT_ALERT_SETTINGS,
} from '../src/lib/alerts/rules';
import { renderAlertEmail } from '../src/lib/alerts/templates';
import { resolveAlertRecipients, getEmailProvider } from '../src/lib/alerts/email';
import { triggerAlert, getOrganizationAlertSettings } from '../src/lib/alerts/service';
import { computeRiskScore } from '../src/lib/risk/computeRiskScore';
import { processScanJob } from '../src/workers/scanProcessor';
import { upsertDiscoveredAsset } from '../src/lib/discovery/upsertAsset';
import { GET as getAlertsRoute } from '../src/app/api/alerts/route';
import {
  GET as getAlertSettingsRoute,
  PATCH as patchAlertSettingsRoute,
} from '../src/app/api/org/alert-settings/route';
import { GET as getFindingsRoute } from '../src/app/api/findings/route';

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

function createMockRequest(
  url: string,
  options: { method?: string; body?: any; token?: string } = {}
): NextRequest {
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

async function runAlertingSystemTests() {
  console.log('🚨 Running Option 5: Alerting & Notification System Tests...\n');

  // =========================================================================
  // Test Suite 1: Rule Engine & Threshold Gating (§2.1 & §2.2)
  // =========================================================================
  console.log('--- Test Suite 1: Rule Engine & Threshold Gating ---');

  assert(
    ALERT_RISK_SCORE_THRESHOLD === 70,
    'ALERT_RISK_SCORE_THRESHOLD is explicitly defined as 70 in code'
  );

  // 1.1 Qualifying CRITICAL finding
  const decisionCrit = shouldAlertOnFinding(
    { severity: 'CRITICAL', confidence: 'CONFIRMED', riskScore: 85 },
    { importance: 'HIGH', type: 'ROOT_DOMAIN' }
  );
  assert(decisionCrit.shouldAlert === true, 'CONFIRMED CRITICAL finding with riskScore >= 70 triggers alert');
  assert(decisionCrit.alertType === 'NEW_CRITICAL_FINDING', 'Assigns NEW_CRITICAL_FINDING alert type');

  // 1.2 Qualifying HIGH finding
  const decisionHigh = shouldAlertOnFinding(
    { severity: 'HIGH', confidence: 'HIGH', riskScore: 72 },
    { importance: 'NORMAL', type: 'SUBDOMAIN' }
  );
  assert(decisionHigh.shouldAlert === true, 'HIGH confidence HIGH severity finding with riskScore >= 70 triggers alert');
  assert(decisionHigh.alertType === 'NEW_HIGH_FINDING', 'Assigns NEW_HIGH_FINDING alert type');

  // 1.3 Confidence Guard: Disqualifies MEDIUM/LOW/INFORMATIONAL confidence
  const decisionLowConf = shouldAlertOnFinding(
    { severity: 'CRITICAL', confidence: 'MEDIUM', riskScore: 90 },
    { importance: 'CRITICAL' }
  );
  assert(decisionLowConf.shouldAlert === false, 'CRITICAL severity with MEDIUM confidence is REJECTED by confidence guard');
  assert(
    Boolean(decisionLowConf.reason?.includes('below required alert threshold')),
    'Reason clearly reports confidence gate failure'
  );

  // 1.4 Asset Importance & Exposure Effect (Risk Score Gate)
  // CRITICAL finding on LOW-importance staging asset -> low computed risk score
  const stagingAsset = {
    fqdn: 'staging.test.com',
    type: 'SUBDOMAIN' as const,
    importance: 'LOW' as const,
    tags: ['staging', 'internal'],
    verificationStatus: 'VERIFIED' as const,
  };
  const stagingRisk = computeRiskScore(
    { severity: 'CRITICAL', confidence: 'CONFIRMED', category: 'TRANSPORT_SECURITY', findingCode: 'TLS_EXPIRED' },
    stagingAsset
  );

  const decisionStaging = shouldAlertOnFinding(
    { severity: 'CRITICAL', confidence: 'CONFIRMED', riskScore: stagingRisk.score },
    stagingAsset
  );
  assert(stagingRisk.score < 70, `Staging asset risk score is below 70 (got: ${stagingRisk.score})`);
  assert(decisionStaging.shouldAlert === false, 'CRITICAL finding on LOW-importance staging asset does NOT generate alert');

  // Same CRITICAL finding on CRITICAL-importance production asset
  const prodAsset = {
    fqdn: 'prod.acme.com',
    type: 'ROOT_DOMAIN' as const,
    importance: 'CRITICAL' as const,
    tags: ['production'],
    verificationStatus: 'VERIFIED' as const,
  };
  const prodRisk = computeRiskScore(
    { severity: 'CRITICAL', confidence: 'CONFIRMED', category: 'TRANSPORT_SECURITY', findingCode: 'TLS_EXPIRED' },
    prodAsset
  );

  const decisionProd = shouldAlertOnFinding(
    { severity: 'CRITICAL', confidence: 'CONFIRMED', riskScore: prodRisk.score },
    prodAsset
  );
  assert(prodRisk.score >= 70, `Production asset risk score is >= 70 (got: ${prodRisk.score})`);
  assert(decisionProd.shouldAlert === true, 'Same CRITICAL finding on CRITICAL-importance production asset DOES generate alert');

  // =========================================================================
  // Test Suite 2: Stricter Bar Than Dashboard Visibility (§2.2)
  // =========================================================================
  console.log('\n--- Test Suite 2: Stricter Bar Than Dashboard Visibility ---');

  const orgDashTestId = 'org-dash-gate-test';
  const userDashAdminId = 'user-dash-admin';

  memoryStore.organizations.set(orgDashTestId, {
    _id: orgDashTestId,
    name: 'Dashboard Gate Org',
    plan: 'PRO',
    scanQuotas: { maxMonitoredDomains: 5, dailyScanLimit: 20, concurrentScans: 2 },
    members: [{ userId: userDashAdminId, role: 'ADMIN', joinedAt: new Date() }],
  });

  memoryStore.users.set(userDashAdminId, {
    _id: userDashAdminId,
    email: 'admin@dashgate.test',
    organizationId: orgDashTestId,
    role: 'ADMIN',
    organizationMemberships: [{ organizationId: orgDashTestId, role: 'ADMIN' }],
  });

  const dashToken = createSessionToken({
    userId: userDashAdminId,
    email: 'admin@dashgate.test',
    role: 'ADMIN',
    organizationId: orgDashTestId,
  });

  // Create finding with riskScore = 55 (visible on dashboard, but fails alert gate of 70)
  const findingVisibleKey = `${orgDashTestId}:hash-visible-55`;
  const findingVisible = {
    _id: 'finding-visible-55',
    id: 'finding-visible-55',
    organizationId: orgDashTestId,
    assetId: 'asset-test-dash',
    findingCode: 'TLS_WEAK_CIPHER',
    title: 'Weak Cipher Supported',
    description: 'Server accepts legacy cipher suite.',
    severity: 'HIGH',
    confidence: 'HIGH',
    riskScore: 55,
    status: 'OPEN',
    dedupHash: 'hash-visible-55',
    createdAt: new Date(),
    lastSeen: new Date(),
  };
  memoryStore.findings.set(findingVisibleKey, findingVisible);

  // 2.1 Verify finding is visible in GET /api/findings
  const getFindingsReq = createMockRequest('http://localhost:3000/api/findings', {
    token: dashToken,
  });
  const getFindingsRes = await getFindingsRoute(getFindingsReq);
  const getFindingsJson = await getFindingsRes.json();

  assert(getFindingsRes.status === 200, 'GET /api/findings returns 200 OK');
  assert(
    getFindingsJson.data.some((f: any) => f.findingCode === 'TLS_WEAK_CIPHER'),
    'Finding with riskScore 55 IS visible on the customer dashboard'
  );

  // 2.2 Verify finding fails alert generation
  const triggerRes = await triggerAlert({
    organizationId: orgDashTestId,
    type: 'NEW_HIGH_FINDING',
    targetName: 'portal.acme.com',
    finding: findingVisible,
  });

  assert(triggerRes.triggered === false, 'Finding with riskScore 55 is REJECTED by alert rule engine');
  assert(
    Boolean(triggerRes.reason?.includes('below alert threshold')),
    'Rejection specifies risk score is below alert threshold'
  );

  // =========================================================================
  // Test Suite 3: Deduplication & Severity Escalation (§2.3)
  // =========================================================================
  console.log('\n--- Test Suite 3: Deduplication & Severity Escalation ---');

  memoryStore.alerts.clear();
  memoryStore.sentEmails = [];

  const orgDedupId = 'org-dedup-test';
  memoryStore.organizations.set(orgDedupId, {
    _id: orgDedupId,
    name: 'Dedup Test Org',
    plan: 'PRO',
    settings: { alertEmail: 'security@deduptest.com' },
  });

  const highFinding = {
    _id: 'finding-dedup-01',
    id: 'finding-dedup-01',
    findingCode: 'HEADER_CSP_MISSING',
    title: 'Missing Content Security Policy',
    severity: 'HIGH',
    confidence: 'CONFIRMED',
    riskScore: 78,
  };

  // Scan 1: First detection -> Generates Alert 1
  const alert1 = await triggerAlert({
    organizationId: orgDedupId,
    type: 'NEW_HIGH_FINDING',
    targetName: 'app.deduptest.com',
    finding: highFinding,
  });

  assert(alert1.triggered === true, 'Scan 1: Generates initial Alert 1');
  assert(alert1.alert.deliveryStatus === 'SENT', 'Alert 1 delivered successfully');

  // Scan 2: Re-detection of identical finding within 7 days -> Suppressed
  const alert2 = await triggerAlert({
    organizationId: orgDedupId,
    type: 'NEW_HIGH_FINDING',
    targetName: 'app.deduptest.com',
    finding: highFinding,
  });

  assert(alert2.triggered === false, 'Scan 2: Re-detected identical finding is SUPPRESSED within 7-day window');
  assert(
    Boolean(alert2.reason?.includes('suppression window')),
    'Reason reports suppression window match'
  );

  // Scan 3: Third identical scan -> Still Suppressed
  const alert3 = await triggerAlert({
    organizationId: orgDedupId,
    type: 'NEW_HIGH_FINDING',
    targetName: 'app.deduptest.com',
    finding: highFinding,
  });

  assert(alert3.triggered === false, 'Scan 3: Third identical scan remains SUPPRESSED');
  assert(
    Array.from(memoryStore.alerts.values()).filter((a) => a.organizationId === orgDedupId).length === 1,
    'Exactly ONE Alert record exists after 3 consecutive scans of identical finding'
  );

  // Scan 4: Severity Escalates (HIGH -> CRITICAL) -> Bypasses suppression window
  const escalatedFinding = {
    ...highFinding,
    severity: 'CRITICAL',
    riskScore: 94,
  };

  const alertEscalated = await triggerAlert({
    organizationId: orgDedupId,
    type: 'NEW_CRITICAL_FINDING',
    targetName: 'app.deduptest.com',
    finding: escalatedFinding,
  });

  assert(alertEscalated.triggered === true, 'Scan 4: Severity escalation (HIGH -> CRITICAL) bypasses suppression window and alerts');
  assert(
    alertEscalated.alert.type === 'NEW_CRITICAL_FINDING',
    'Escalated alert has NEW_CRITICAL_FINDING type'
  );

  // 3.5 Auto-Reopen Exception: Bypasses suppression window entirely
  const alertReopened = await triggerAlert({
    organizationId: orgDedupId,
    type: 'FINDING_AUTO_REOPENED',
    targetName: 'app.deduptest.com',
    finding: highFinding,
  });

  assert(alertReopened.triggered === true, 'FINDING_AUTO_REOPENED bypasses suppression window and triggers immediate alert');
  assert(alertReopened.alert.type === 'FINDING_AUTO_REOPENED', 'Alert type is FINDING_AUTO_REOPENED');

  // =========================================================================
  // Test Suite 4: Passive Asset Discovery Alerts (§2.1)
  // =========================================================================
  console.log('\n--- Test Suite 4: Passive Asset Discovery Alerts ---');

  // 4.1 Passive discovery via CT_LOG -> Triggers alert
  const discDecisionCt = shouldAlertOnAssetDiscovery('CT_LOG');
  assert(discDecisionCt.shouldAlert === true, 'CT_LOG discovery qualifies for NEW_ASSET_DISCOVERED alert');

  // 4.2 Passive discovery via DNS_PERMUTATION -> Triggers alert
  const discDecisionDns = shouldAlertOnAssetDiscovery('DNS_PERMUTATION');
  assert(discDecisionDns.shouldAlert === true, 'DNS_PERMUTATION discovery qualifies for NEW_ASSET_DISCOVERED alert');

  // 4.3 Manual addition -> Suppressed
  const discDecisionManual = shouldAlertOnAssetDiscovery('MANUAL');
  assert(discDecisionManual.shouldAlert === false, 'MANUAL addition is REJECTED from discovery alerting');
  assert(
    Boolean(discDecisionManual.reason?.includes('Manual asset additions do not trigger')),
    'Reason clarifies manual additions are ignored'
  );

  // =========================================================================
  // Test Suite 5: Plain-Language Email Templates & Delivery (§3)
  // =========================================================================
  console.log('\n--- Test Suite 5: Plain-Language Email Templates & Delivery ---');

  const renderedCrit = renderAlertEmail({
    type: 'NEW_CRITICAL_FINDING',
    severity: 'CRITICAL',
    targetName: 'vpn.acme.com',
    findingTitle: 'SSL Certificate Expired',
    riskScore: 92,
    remediationSummary: 'Renew TLS certificate with valid certificate authority.',
    targetUrl: 'https://app.pliora.io/findings/123',
  });

  assert(
    renderedCrit.subject.includes('[CRITICAL SECURITY ALERT]'),
    'Email subject contains high-priority tag'
  );
  assert(
    renderedCrit.html.includes('Why This Matters') && renderedCrit.html.includes('Recommended Action'),
    'Email contains plain-language "Why This Matters" and "Recommended Action" cards'
  );
  assert(
    renderedCrit.html.includes('https://app.pliora.io/findings/123'),
    'Email includes link to authenticated dashboard'
  );
  assert(
    !renderedCrit.html.includes('rawObservation') && !renderedCrit.html.includes('contentHash'),
    'Invariant satisfied: Email body contains ZERO sensitive technical telemetry'
  );

  // Recipient resolution test
  const orgRecipId = 'org-recip-test';
  const ownerUser = {
    _id: 'user-owner',
    email: 'owner@acme.test',
    organizationMemberships: [{ organizationId: orgRecipId, role: 'OWNER' }],
  };
  const adminUser = {
    _id: 'user-admin',
    email: 'admin@acme.test',
    organizationMemberships: [{ organizationId: orgRecipId, role: 'ADMIN' }],
  };
  const viewerUser = {
    _id: 'user-viewer',
    email: 'viewer@acme.test',
    organizationMemberships: [{ organizationId: orgRecipId, role: 'VIEWER' }],
  };

  memoryStore.users.set(ownerUser._id, ownerUser);
  memoryStore.users.set(adminUser._id, adminUser);
  memoryStore.users.set(viewerUser._id, viewerUser);

  const resolvedRecipients = await resolveAlertRecipients(orgRecipId);
  assert(resolvedRecipients.includes('owner@acme.test'), 'Resolves OWNER email');
  assert(resolvedRecipients.includes('admin@acme.test'), 'Resolves ADMIN email');
  assert(!resolvedRecipients.includes('viewer@acme.test'), 'Strictly EXCLUDES VIEWER email from notifications');

  // =========================================================================
  // Test Suite 6: Per-Organization Alert Preferences (§4)
  // =========================================================================
  console.log('\n--- Test Suite 6: Per-Organization Alert Preferences ---');

  const prefOrgId = 'org-prefs-test';
  const prefAdminId = 'user-prefs-admin';
  const prefViewerId = 'user-prefs-viewer';

  memoryStore.organizations.set(prefOrgId, {
    _id: prefOrgId,
    name: 'Preferences Org',
    plan: 'PRO',
    scanQuotas: { maxMonitoredDomains: 5, dailyScanLimit: 20, concurrentScans: 2 },
    members: [
      { userId: prefAdminId, role: 'ADMIN', joinedAt: new Date() },
      { userId: prefViewerId, role: 'VIEWER', joinedAt: new Date() },
    ],
  });

  memoryStore.users.set(prefAdminId, {
    _id: prefAdminId,
    email: 'admin@prefs.test',
    role: 'ADMIN',
    organizationMemberships: [{ organizationId: prefOrgId, role: 'ADMIN' }],
  });

  memoryStore.users.set(prefViewerId, {
    _id: prefViewerId,
    email: 'viewer@prefs.test',
    role: 'VIEWER',
    organizationMemberships: [{ organizationId: prefOrgId, role: 'VIEWER' }],
  });

  const adminPrefToken = createSessionToken({
    userId: prefAdminId,
    email: 'admin@prefs.test',
    role: 'ADMIN',
    organizationId: prefOrgId,
  });

  const viewerPrefToken = createSessionToken({
    userId: prefViewerId,
    email: 'viewer@prefs.test',
    role: 'VIEWER',
    organizationId: prefOrgId,
  });

  // 6.1 GET /api/org/alert-settings returns default settings
  const getSettingsReq = createMockRequest('http://localhost:3000/api/org/alert-settings', {
    token: adminPrefToken,
  });
  const getSettingsRes = await getAlertSettingsRoute(getSettingsReq);
  const getSettingsJson = await getSettingsRes.json();

  assert(getSettingsRes.status === 200, 'GET /api/org/alert-settings returns 200 OK');
  assert(getSettingsJson.data.minRiskScore === 70, 'Default minRiskScore is 70');
  assert(getSettingsJson.data.sendToAdmins === true, 'Default sendToAdmins is true');

  // 6.2 Mutation by VIEWER is denied with 403 Forbidden
  const patchViewerReq = createMockRequest('http://localhost:3000/api/org/alert-settings', {
    method: 'PATCH',
    token: viewerPrefToken,
    body: { minRiskScore: 80 },
  });
  const patchViewerRes = await patchAlertSettingsRoute(patchViewerReq);
  assert(patchViewerRes.status === 403, 'PATCH /api/org/alert-settings by VIEWER is denied with 403 Forbidden');

  // 6.3 Mutation by ADMIN succeeds and disables NEW_ASSET_DISCOVERED
  const patchAdminReq = createMockRequest('http://localhost:3000/api/org/alert-settings', {
    method: 'PATCH',
    token: adminPrefToken,
    body: {
      enabledTypes: ['NEW_CRITICAL_FINDING', 'NEW_HIGH_FINDING'],
      minRiskScore: 75,
      additionalEmails: ['alerts-external@test.com'],
    },
  });
  const patchAdminRes = await patchAlertSettingsRoute(patchAdminReq);
  const patchAdminJson = await patchAdminRes.json();

  assert(patchAdminRes.status === 200, 'PATCH /api/org/alert-settings by ADMIN succeeds with 200 OK');
  assert(patchAdminJson.data.minRiskScore === 75, 'Updated minRiskScore to 75');
  assert(
    !patchAdminJson.data.enabledTypes.includes('NEW_ASSET_DISCOVERED'),
    'NEW_ASSET_DISCOVERED disabled in organization settings'
  );

  // 6.4 Preference Suppression Verification
  const discDecisionCustom = shouldAlertOnAssetDiscovery('CT_LOG', patchAdminJson.data);
  assert(
    discDecisionCustom.shouldAlert === false,
    'Custom org settings successfully suppress NEW_ASSET_DISCOVERED'
  );

  const critDecisionCustom = shouldAlertOnFinding(
    { severity: 'CRITICAL', confidence: 'CONFIRMED', riskScore: 80 },
    {},
    patchAdminJson.data
  );
  assert(
    critDecisionCustom.shouldAlert === true,
    'CRITICAL finding continues alerting normally under custom settings'
  );

  // =========================================================================
  // Test Suite 7: Operational SCAN_FAILED Alerts (§5)
  // =========================================================================
  console.log('\n--- Test Suite 7: Operational SCAN_FAILED Alerts ---');

  const opsOrgId = 'org-ops-test';
  memoryStore.organizations.set(opsOrgId, {
    _id: opsOrgId,
    name: 'Ops Test Org',
    plan: 'PRO',
    settings: { alertEmail: 'ops@pliora.test' },
  });

  const scanAlertRes = await triggerAlert({
    organizationId: opsOrgId,
    type: 'SCAN_FAILED',
    targetName: 'unresponsive-target.com',
    error: 'DNS resolution timed out after 3 retries.',
  });

  assert(scanAlertRes.triggered === true, 'Operational SCAN_FAILED triggers separate alert');
  assert(scanAlertRes.alert.severity === 'MEDIUM', 'Operational alert assigned MEDIUM severity');
  assert(scanAlertRes.alert.summary.includes('DNS resolution timed out'), 'Alert summary captures failure reason');

  // =========================================================================
  // Test Suite 8: Alert History API (GET /api/alerts)
  // =========================================================================
  console.log('\n--- Test Suite 8: Alert History API ---');

  const getAlertsReq = createMockRequest('http://localhost:3000/api/alerts?page=1&limit=10', {
    token: adminPrefToken,
  });
  const getAlertsRes = await getAlertsRoute(getAlertsReq);
  const getAlertsJson = await getAlertsRes.json();

  assert(getAlertsRes.status === 200, 'GET /api/alerts returns 200 OK');
  assert(getAlertsJson.success === true, 'Returns success: true');
  assert(Array.isArray(getAlertsJson.data), 'Returns data array');
  assert(typeof getAlertsJson.pagination.total === 'number', 'Returns pagination metadata');

  // =========================================================================
  // Final Test Summary
  // =========================================================================
  console.log('\n=============================================');
  console.log(` Option 5 Test Summary: ${passed} Passed, ${failed} Failed`);
  console.log('=============================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runAlertingSystemTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
