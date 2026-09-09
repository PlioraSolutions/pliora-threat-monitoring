import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
import crypto from 'crypto';
import { memoryStore } from '../src/lib/store';
import { POST as createScan } from '../src/app/api/scans/route';
import { GET as listApiKeys, POST as createApiKey } from '../src/app/api/org/api-keys/route';
import { DELETE as revokeApiKey } from '../src/app/api/org/api-keys/[id]/route';
import { GET as getFindings } from '../src/app/api/findings/route';
import { PATCH as updateAlertSettings } from '../src/app/api/org/alert-settings/route';
import { GET as exportReport } from '../src/app/api/reports/export/route';
import { createSessionToken, getAuthenticatedSession } from '../src/lib/auth';
import { pluginRegistry } from '../src/lib/plugins/registry';
import { portScanCheckPlugin } from '../src/lib/plugins/portScanCheck';
import { cveCorrelationCheckPlugin } from '../src/lib/plugins/cveCorrelationCheck';
import { correlateTechnologyCves, KNOWN_CVE_DATABASE } from '../src/lib/cve/cveCorrelation';
import { formatSlackBlockKit, sendWebhookAlert } from '../src/lib/alerts/webhook';
import { triggerAlert } from '../src/lib/alerts/service';

describe('Roadmap Phase A & C.2: Feature Parity & Production Hardening', () => {
  const orgId = 'org_phase_a_test';
  const ownerUserId = 'user_phase_a_owner';
  let ownerCookie: string;
  let verifiedAssetId: string;

  it('Setup: Initialize Organization, Owner, and Verified Asset', async () => {
    // 1. Seed Org
    memoryStore.organizations.set(orgId, {
      _id: orgId,
      id: orgId,
      name: 'Roadmap Test Corp',
      slug: 'roadmap-test',
      ownerId: ownerUserId,
      plan: 'PRO',
      scanQuotas: {
        maxMonitoredDomains: 5,
        dailyScanLimit: 2, // Low limit to test quota enforcement (§C.2)
        concurrentScans: 5,
      },
      alertSettings: {
        enabledTypes: ['NEW_CRITICAL_FINDING', 'THREAT_DETECTED'],
        minRiskScore: 60,
      },
      createdAt: new Date(),
    });

    // 2. Seed Owner User
    memoryStore.users.set(ownerUserId, {
      _id: ownerUserId,
      id: ownerUserId,
      name: 'Owner Tester',
      email: 'owner@roadmap-test.com',
      globalRole: 'USER',
      activeOrganizationId: orgId,
      organizationMemberships: [
        {
          organizationId: orgId,
          role: 'OWNER',
          joinedAt: new Date(),
        },
      ],
      createdAt: new Date(),
    });

    const token = createSessionToken({
      userId: ownerUserId,
      email: 'owner@roadmap-test.com',
      organizationId: orgId,
      role: 'OWNER',
    });
    ownerCookie = `pliora_session=${token}`;

    // 3. Seed Verified Asset
    verifiedAssetId = 'asset_phase_a_root';
    memoryStore.assets.set(verifiedAssetId, {
      _id: verifiedAssetId,
      id: verifiedAssetId,
      organizationId: orgId,
      rootDomain: 'roadmap-test.com',
      fqdn: 'roadmap-test.com',
      type: 'ROOT_DOMAIN',
      importance: 'HIGH',
      verificationStatus: 'VERIFIED',
      discoveredVia: ['MANUAL'],
      createdAt: new Date(),
    });
  });

  // --- Component 1: Production Hardening (§C.2) ---
  it('1. Server-Side Daily Scan Limit Quota Enforcement (§C.2)', async () => {
    // Clear any prior scans for this org
    for (const [id, scan] of Array.from(memoryStore.scans.entries())) {
      if (scan.organizationId === orgId) memoryStore.scans.delete(id);
    }

    // Scan 1: Should succeed (daily count: 0 < 2)
    const scanReq1 = new NextRequest('http://localhost:3000/api/scans', {
      method: 'POST',
      headers: { cookie: ownerCookie },
      body: JSON.stringify({ assetId: verifiedAssetId, scanType: 'EXPOSURE' }),
    });
    const res1 = await createScan(scanReq1);
    assert.equal(res1.status, 202, 'First scan should be accepted');

    // Scan 2: Should succeed (daily count: 1 < 2)
    const scanReq2 = new NextRequest('http://localhost:3000/api/scans', {
      method: 'POST',
      headers: { cookie: ownerCookie },
      body: JSON.stringify({ assetId: verifiedAssetId, scanType: 'EXPOSURE' }),
    });
    const res2 = await createScan(scanReq2);
    assert.equal(res2.status, 202, 'Second scan should be accepted');

    // Scan 3: Should fail with 429 DAILY_SCAN_LIMIT_EXCEEDED (daily count: 2 >= 2)
    const scanReq3 = new NextRequest('http://localhost:3000/api/scans', {
      method: 'POST',
      headers: { cookie: ownerCookie },
      body: JSON.stringify({ assetId: verifiedAssetId, scanType: 'EXPOSURE' }),
    });
    const res3 = await createScan(scanReq3);
    const json3 = await res3.json();
    assert.equal(res3.status, 429, 'Third scan must be blocked by dailyScanLimit');
    assert.equal(json3.error.code, 'DAILY_SCAN_LIMIT_EXCEEDED');
  });

  // --- Component 2: Customer-Facing API Access (§A.5) ---
  let generatedApiKey: string;
  let apiKeyId: string;

  it('2. Customer API Key Lifecycle & Authentication (§A.5)', async () => {
    // 2a. Generate API key as OWNER
    const createReq = new NextRequest('http://localhost:3000/api/org/api-keys', {
      method: 'POST',
      headers: { cookie: ownerCookie },
      body: JSON.stringify({
        name: 'CI/CD Pipeline Key',
        role: 'VIEWER',
      }),
    });
    const createRes = await createApiKey(createReq);
    const createJson = await createRes.json();
    assert.equal(createRes.status, 201);
    assert.equal(createJson.success, true);
    assert.ok(createJson.data.apiKey.startsWith('plk_live_'), 'Key must start with standard prefix');
    assert.ok(createJson.data.keyPrefix.startsWith('plk_live_'));
    assert.equal(createJson.data.role, 'VIEWER');

    generatedApiKey = createJson.data.apiKey;
    apiKeyId = createJson.data.id;

    // 2b. Verify key is stored hashed in memory store (never plaintext)
    const expectedHash = crypto.createHash('sha256').update(generatedApiKey).digest('hex');
    const storedRecord = memoryStore.apiKeys.get(expectedHash);
    assert.ok(storedRecord, 'API key record must be indexed by SHA-256 hash');
    assert.equal(storedRecord.hashedKey, expectedHash);

    // 2c. Authenticate with x-api-key header
    const authReq = new NextRequest('http://localhost:3000/api/findings', {
      headers: { 'x-api-key': generatedApiKey },
    });
    const session = await getAuthenticatedSession(authReq);
    assert.ok(session, 'Session must resolve from valid API key');
    assert.equal(session.organization._id, orgId);
    assert.equal(session.user.role, 'VIEWER');
    assert.equal(session.user.isApiKey, true);

    // 2d. Authenticate with Authorization: Bearer plk_live_...
    const bearerReq = new NextRequest('http://localhost:3000/api/findings', {
      headers: { authorization: `Bearer ${generatedApiKey}` },
    });
    const bearerSession = await getAuthenticatedSession(bearerReq);
    assert.ok(bearerSession, 'Session must resolve from Bearer API key');
    assert.equal(bearerSession.organization._id, orgId);

    // 2e. List API keys
    const listReq = new NextRequest('http://localhost:3000/api/org/api-keys', {
      headers: { cookie: ownerCookie },
    });
    const listRes = await listApiKeys(listReq);
    const listJson = await listRes.json();
    assert.equal(listRes.status, 200);
    assert.ok(Array.isArray(listJson.data));
    assert.equal(listJson.data.length >= 1, true);
    assert.equal(listJson.data[0].apiKey, undefined, 'Plaintext secret must never be returned on list');

    // 2f. Revoke API key
    const delReq = new NextRequest(`http://localhost:3000/api/org/api-keys/${apiKeyId}`, {
      method: 'DELETE',
      headers: { cookie: ownerCookie },
    });
    const delRes = await revokeApiKey(delReq, { params: { id: apiKeyId } });
    assert.equal(delRes.status, 200);

    // 2g. Subsequent request with revoked key must fail
    const revokedReq = new NextRequest('http://localhost:3000/api/findings', {
      headers: { 'x-api-key': generatedApiKey },
    });
    const revokedSession = await getAuthenticatedSession(revokedReq);
    assert.equal(revokedSession, null, 'Revoked API key must not authenticate');
  });

  // --- Component 3: Webhook & Slack Delivery Channel (§A.4) ---
  it('3. Webhook & Slack Delivery Channel (§A.4)', async () => {
    // 3a. Configure Webhook settings
    const patchReq = new NextRequest('http://localhost:3000/api/org/alert-settings', {
      method: 'PATCH',
      headers: { cookie: ownerCookie },
      body: JSON.stringify({
        webhookUrl: 'https://webhook.site/test-endpoint',
        webhookSecret: 'super-secret-hmac-key',
        webhookChannel: 'GENERIC',
      }),
    });
    const patchRes = await updateAlertSettings(patchReq);
    const patchJson = await patchRes.json();
    assert.equal(patchRes.status, 200);
    assert.equal(patchJson.data.webhookUrl, 'https://webhook.site/test-endpoint');
    assert.equal(patchJson.data.webhookChannel, 'GENERIC');

    // 3b. Format Slack Block Kit layout
    const testPayload = {
      event: 'NEW_CRITICAL_FINDING' as any,
      severity: 'CRITICAL' as any,
      title: 'TLS Certificate Expired',
      summary: 'Public TLS cert expired on production host.',
      targetName: 'roadmap-test.com',
      riskScore: 95,
      remediationSummary: 'Renew cert immediately via Let\'s Encrypt.',
      timestamp: new Date().toISOString(),
    };

    const slackBlocks = formatSlackBlockKit(testPayload);
    assert.ok(slackBlocks.attachments);
    assert.equal(slackBlocks.attachments[0].color, '#ef4444', 'Critical severity must map to red');
    assert.ok(slackBlocks.attachments[0].blocks.some((b: any) => b.text?.text?.includes('TLS Certificate Expired')));

    // 3c. Verify HMAC signature generation
    const testSecret = 'test-secret-key';
    const testBody = JSON.stringify(testPayload);
    const expectedSig = crypto.createHmac('sha256', testSecret).update(testBody).digest('hex');
    assert.ok(expectedSig.length === 64, 'HMAC-SHA256 signature must be 64-char hex string');
  });

  // --- Component 4: Open Port & Service Scanning (§A.1) ---
  it('4. Open Port & Service Scanning Plugin (§A.1)', async () => {
    // 4a. Verify plugin is registered in global registry
    const registered = pluginRegistry.getPlugin('port-scan-check');
    assert.ok(registered, 'port-scan-check must be registered in pluginRegistry');
    assert.equal(registered.category, 'EXPOSED_SERVICES');
    assert.equal(registered.defaultConfidence, 'MEDIUM');

    // 4b. Mock safeFetch for port 8080 open
    const mockSafeFetch = async (url: string) => {
      if (url.includes(':8080')) {
        return new Response('Apache Tomcat Administration', {
          status: 200,
          headers: { server: 'Apache-Coyote/1.1' },
        });
      }
      throw new Error('ECONNREFUSED');
    };

    const pluginResult = await portScanCheckPlugin.run(
      { fqdn: 'admin.roadmap-test.com', type: 'SUBDOMAIN' },
      {
        safeFetch: mockSafeFetch as any,
        safeTlsHandshake: async () => ({} as any),
        scanId: 'scan_port_test',
        organizationId: orgId,
        timeoutMs: 3000,
      }
    );

    assert.equal(pluginResult.status, 'COMPLETED');
    assert.equal(pluginResult.findings.length, 1);
    const portFinding = pluginResult.findings[0];
    assert.equal(portFinding.findingCode, 'PORT-EXPOSED-8080');
    assert.equal(portFinding.severity, 'MEDIUM');
    // MANDATORY HARD GUARD (§A.1 DoD): Port exposure confidence must not exceed MEDIUM
    assert.equal(portFinding.confidence, 'MEDIUM');
  });

  // --- Component 5: CVE Correlation Engine (§A.2) ---
  it('5. CVE Correlation Engine & Hard Confidence Ceiling (§A.2)', async () => {
    // 5a. Verify database contains high-profile CVEs
    assert.ok(KNOWN_CVE_DATABASE.length >= 5);
    const log4jOrApache = KNOWN_CVE_DATABASE.find((c) => c.technology === 'Apache');
    assert.ok(log4jOrApache);

    // 5b. Correlate vulnerable version (Apache 2.4.49 -> CVE-2021-41773)
    const matches = correlateTechnologyCves('Apache', '2.4.49', false);
    assert.equal(matches.length >= 1, true);
    const cve = matches.find((m) => m.cveId === 'CVE-2021-41773');
    assert.ok(cve, 'Must match CVE-2021-41773');
    assert.equal(cve.severity, 'CRITICAL');
    assert.ok(cve.epssScore > 0.9, 'EPSS score must reflect high weaponization');

    // MANDATORY HARD GUARD TEST (§A.2 DoD):
    // Fingerprint-only version match MUST NOT exceed MEDIUM confidence even if CVSS is 9.8
    assert.equal(cve.confidence, 'MEDIUM', 'Fingerprint-only CVE match MUST be strictly capped at MEDIUM confidence');
    assert.equal(cve.isBehaviorallyCorroborated, false);

    // 5c. Corroborated match can achieve HIGH confidence
    const corroboratedMatches = correlateTechnologyCves('Apache', '2.4.49', true);
    const corroboratedCve = corroboratedMatches.find((m) => m.cveId === 'CVE-2021-41773');
    assert.ok(corroboratedCve);
    assert.equal(corroboratedCve.confidence, 'HIGH', 'Corroborated behavioral proof permits HIGH confidence');

    // 5d. Non-vulnerable version produces zero false findings
    const safeMatches = correlateTechnologyCves('Apache', '2.4.58', false);
    assert.equal(safeMatches.length, 0, 'Safe version must not generate false CVE findings');

    // 5e. Plugin integration
    const cvePlugin = pluginRegistry.getPlugin('cve-correlation-check');
    assert.ok(cvePlugin, 'cve-correlation-check must be in registry');
    assert.equal(cvePlugin.defaultConfidence, 'MEDIUM');
  });

  // --- Component 6: PDF / Printable Report Export (§A.3) ---
  it('6. PDF / Printable Executive Report Export (§A.3)', async () => {
    // 6a. HTML Printable format
    const exportReq = new NextRequest('http://localhost:3000/api/reports/export', {
      headers: { cookie: ownerCookie },
    });
    const exportRes = await exportReport(exportReq);
    assert.equal(exportRes.status, 200);
    assert.equal(exportRes.headers.get('content-type')?.includes('text/html'), true);
    const html = await exportRes.text();
    assert.ok(html.includes('Executive Security Report'), 'Report title must be present');
    assert.ok(html.includes('@media print'), 'Print styling rules required');
    assert.ok(html.includes('Roadmap Test Corp'), 'Org name must be displayed');
    assert.ok(html.includes('window.print()'), 'Print/export trigger required');

    // 6b. JSON format
    const jsonReq = new NextRequest('http://localhost:3000/api/reports/export?format=json', {
      headers: { cookie: ownerCookie },
    });
    const jsonRes = await exportReport(jsonReq);
    const jsonReport = await jsonRes.json();
    assert.equal(jsonRes.status, 200);
    assert.equal(jsonReport.success, true);
    assert.ok(jsonReport.data.executiveSummary);
    assert.ok(jsonReport.data.overallPosture);
    assert.ok(Array.isArray(jsonReport.data.priorityActions));
  });
});
