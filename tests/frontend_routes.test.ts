process.env.FORCE_MEMORY_STORE = 'true';

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
import { memoryStore } from '../src/lib/store';
import { GET as getMe } from '../src/app/api/auth/me/route';
import { POST as registerUser } from '../src/app/api/auth/register/route';
import { GET as getMembers } from '../src/app/api/org/members/route';
import { GET as getAlertSettings, PATCH as updateAlertSettings } from '../src/app/api/org/alert-settings/route';
import { GET as getRiskScore } from '../src/app/api/risk-score/route';
import { GET as getRiskHistory } from '../src/app/api/risk-score/history/route';
import { GET as getFindings } from '../src/app/api/findings/route';
import { GET as getFindingDetail, PATCH as updateFindingStatus } from '../src/app/api/findings/[id]/route';
import { GET as explainFinding } from '../src/app/api/findings/[id]/explain/route';
import { GET as getThreats } from '../src/app/api/threats/route';
import { POST as triggerThreatScan } from '../src/app/api/threats/scan/route';
import { GET as explainThreat } from '../src/app/api/threats/[id]/explain/route';
import { PATCH as updateThreatStatus } from '../src/app/api/threats/[id]/route';
import { GET as getAssets, POST as addAsset } from '../src/app/api/assets/route';
import { GET as getExecutiveSummary } from '../src/app/api/reports/executive-summary/route';
import { POST as freeAssessment } from '../src/app/api/free-assessment/route';
import { createSessionToken } from '../src/lib/auth';

describe('Option 8: Frontend Customer Dashboard Endpoints & Contracts', () => {
  let ownerCookie: string;
  let viewerCookie: string;
  let orgId: string;
  let ownerUserId: string;
  let viewerUserId: string;

  it('1. User Registration & Auth Me Role Integration', async () => {
    const testEmail = `founder_${Date.now()}_${Math.random().toString(36).slice(2, 7)}@frontend-test.com`;
    const regReq = new NextRequest('http://localhost:3000/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Founder User',
        organizationName: 'Frontend Test Corp',
        email: testEmail,
        password: 'Password123!',
      }),
    });

    const regRes = await registerUser(regReq);
    const regJson = await regRes.json();
    assert.equal(regRes.status, 201, 'Registration should succeed');
    assert.equal(regJson.success, true);
    assert.ok(regJson.data.token, 'Token must be issued');

    ownerCookie = `pliora_session=${regJson.data.token}`;
    orgId = regJson.data.organization.id;
    ownerUserId = regJson.data.user.id;

    // Verify GET /api/auth/me returns role: 'OWNER'
    const meReq = new NextRequest('http://localhost:3000/api/auth/me', {
      headers: { cookie: ownerCookie },
    });
    const meRes = await getMe(meReq);
    const meJson = await meRes.json();
    assert.equal(meRes.status, 200);
    assert.equal(meJson.data.user.role, 'OWNER', 'Owner role must be present in auth/me payload');
    assert.equal(meJson.data.organization.name, 'Frontend Test Corp');
  });

  it('2. Onboarding Flow: Add Asset & Verification Token Generation', async () => {
    const addReq = new NextRequest('http://localhost:3000/api/assets', {
      method: 'POST',
      headers: { cookie: ownerCookie },
      body: JSON.stringify({
        domain: 'frontend-test.com',
        importance: 'CRITICAL',
      }),
    });

    const addRes = await addAsset(addReq);
    const addJson = await addRes.json();
    assert.equal(addRes.status, 201);
    assert.equal(addJson.success, true);
    assert.ok(addJson.data.verificationToken, 'Verification token must be generated');
    assert.equal(addJson.data.verificationStatus, 'PENDING');
    assert.equal(addJson.data.importance, 'CRITICAL');

    // Mark verified in memory store for downstream scans
    const assetId = addJson.data._id || addJson.data.id;
    const storedAsset = memoryStore.assets.get(assetId);
    assert.ok(storedAsset);
    storedAsset.verificationStatus = 'VERIFIED';
    memoryStore.assets.set(assetId, storedAsset);
  });

  it('3. Dashboard Data Feeds: Risk Score, History, and Assets', async () => {
    // 3a. Risk Score
    const scoreReq = new NextRequest('http://localhost:3000/api/risk-score', {
      headers: { cookie: ownerCookie },
    });
    const scoreRes = await getRiskScore(scoreReq);
    const scoreJson = await scoreRes.json();
    assert.equal(scoreRes.status, 200);
    assert.ok(scoreJson.data);
    // API returns: { score, grade, securityPosture, factors, findingCounts, explanation }
    assert.equal(typeof scoreJson.data.score, 'number', 'score must be a number');
    assert.ok(['A', 'B', 'C', 'D', 'F'].includes(scoreJson.data.grade), 'grade must be A-F');
    assert.equal(typeof scoreJson.data.securityPosture, 'number', 'securityPosture must be present');

    // 3b. Score History
    const histReq = new NextRequest('http://localhost:3000/api/risk-score/history', {
      headers: { cookie: ownerCookie },
    });
    const histRes = await getRiskHistory(histReq);
    const histJson = await histRes.json();
    assert.equal(histRes.status, 200);
    assert.ok(Array.isArray(histJson.data), 'History should be an array');

    // 3c. Assets Catalog
    const assetsReq = new NextRequest('http://localhost:3000/api/assets', {
      headers: { cookie: ownerCookie },
    });
    const assetsRes = await getAssets(assetsReq);
    const assetsJson = await assetsRes.json();
    assert.equal(assetsRes.status, 200);
    assert.equal(assetsJson.data.length >= 1, true);
    assert.equal(assetsJson.data[0].fqdn, 'frontend-test.com');
  });

  it('4. Findings Feed, Detail, AI Explain & Status Mutation', async () => {
    // Seed an open finding
    const findingId = 'f_fe_test_01';
    const asset = Array.from(memoryStore.assets.values()).find(
      (a) => a.organizationId.toString() === orgId
    )!;
    assert.ok(asset, 'Asset must exist');

    memoryStore.findings.set(findingId, {
      _id: findingId,
      id: findingId,
      organizationId: orgId,
      assetId: asset._id || asset.id,
      assetFqdn: asset.fqdn,
      category: 'TRANSPORT_SECURITY',
      findingCode: 'TLS_CERT_EXPIRED',
      title: 'Active TLS Certificate is Expired',
      severity: 'CRITICAL',
      confidence: 'CONFIRMED',
      status: 'OPEN',
      riskScore: 85, // pre-computed by scan pipeline; route returns as-is
      summary: 'Public TLS certificate expired on frontend-test.com.',
      businessImpact: 'Browsers block user traffic with privacy alerts.',
      recommendedAction: 'Renew certificate immediately via Certbot.',
      dedupHash: 'dedup_fe_01',
      lastSeen: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    // 4a. List findings
    const listReq = new NextRequest('http://localhost:3000/api/findings?status=OPEN&sortBy=riskScore', {
      headers: { cookie: ownerCookie },
    });
    const listRes = await getFindings(listReq);
    const listJson = await listRes.json();
    assert.equal(listRes.status, 200);
    assert.equal(listJson.data.length >= 1, true);
    const item = listJson.data.find((f: any) => f.id === findingId);
    assert.ok(item, 'Seeded finding must be returned');
    assert.equal(item.severity, 'CRITICAL');
    assert.ok(item.riskScore > 0, 'Risk score must be computed');

    // 4b. Finding detail
    const detailReq = new NextRequest(`http://localhost:3000/api/findings/${findingId}`, {
      headers: { cookie: ownerCookie },
    });
    const detailRes = await getFindingDetail(detailReq, { params: { id: findingId } } as any);
    const detailJson = await detailRes.json();
    assert.equal(detailRes.status, 200);
    assert.equal(detailJson.data.id, findingId);

    // 4c. AI Explain
    const explainReq = new NextRequest(`http://localhost:3000/api/findings/${findingId}/explain`, {
      headers: { cookie: ownerCookie },
    });
    const explainRes = await explainFinding(explainReq, { params: { id: findingId } } as any);
    const explainJson = await explainRes.json();
    assert.equal(explainRes.status, 200);
    assert.ok(explainJson.data.explanation, 'Explanation text must be present');
    assert.ok(Array.isArray(explainJson.data.remediationSteps), 'Remediation steps array required');
    assert.ok(explainJson.data.confidenceCaveat, 'Confidence caveat required');

    // 4d. Status Mutation (Mark Resolved)
    const patchReq = new NextRequest(`http://localhost:3000/api/findings/${findingId}`, {
      method: 'PATCH',
      headers: { cookie: ownerCookie },
      body: JSON.stringify({ status: 'RESOLVED' }),
    });
    const patchRes = await updateFindingStatus(patchReq, { params: { id: findingId } } as any);
    const patchJson = await patchRes.json();
    assert.equal(patchRes.status, 200);
    assert.equal(patchJson.data.status, 'RESOLVED');
  });

  it('5. Threats, Corroboration & AI Explain Feed', async () => {
    const threatId = 't_fe_test_01';
    memoryStore.threats.set(threatId, {
      _id: threatId,
      id: threatId,
      organizationId: orgId,
      indicator: 'frontend-t3st.com',
      mutationType: 'homoglyph',
      similarityScore: 92,
      corroborationScore: 80,
      severity: 'HIGH',
      confidence: 'HIGH',
      status: 'OPEN',
      corroborationFactors: {
        hasDnsA: true,
        hasMx: true,
        isFreshRegistration: true,
        asnOrg: 'Hostinger',
      },
      dedupKey: 'dedup_threat_01',
      firstSeen: new Date(),
      lastSeen: new Date(),
      createdAt: new Date(),
    });

    // 5a. List threats
    const listReq = new NextRequest('http://localhost:3000/api/threats', {
      headers: { cookie: ownerCookie },
    });
    const listRes = await getThreats(listReq);
    const listJson = await listRes.json();
    assert.equal(listRes.status, 200);
    assert.equal(listJson.data.length >= 1, true);

    // 5b. Explain threat
    const expReq = new NextRequest(`http://localhost:3000/api/threats/${threatId}/explain`, {
      headers: { cookie: ownerCookie },
    });
    const expRes = await explainThreat(expReq, { params: { id: threatId } } as any);
    const expJson = await expRes.json();
    assert.equal(expRes.status, 200);
    assert.ok(expJson.data.explanation);

    // 5c. Mutate threat status to MONITORING
    const patchReq = new NextRequest(`http://localhost:3000/api/threats/${threatId}`, {
      method: 'PATCH',
      headers: { cookie: ownerCookie },
      body: JSON.stringify({ status: 'MONITORING' }),
    });
    const patchRes = await updateThreatStatus(patchReq, { params: { id: threatId } } as any);
    const patchJson = await patchRes.json();
    assert.equal(patchRes.status, 200);
    assert.equal(patchJson.data.status, 'MONITORING');
  });

  it('6. Alert Preferences & Organization Team Members', async () => {
    // 6a. GET /api/org/alert-settings
    const getSetReq = new NextRequest('http://localhost:3000/api/org/alert-settings', {
      headers: { cookie: ownerCookie },
    });
    const getSetRes = await getAlertSettings(getSetReq);
    const getSetJson = await getSetRes.json();
    assert.equal(getSetRes.status, 200);
    assert.equal(getSetJson.data.minRiskScore, 70);

    // 6b. PATCH /api/org/alert-settings
    const patchSetReq = new NextRequest('http://localhost:3000/api/org/alert-settings', {
      method: 'PATCH',
      headers: { cookie: ownerCookie },
      body: JSON.stringify({
        minRiskScore: 75,
        enabledTypes: ['NEW_CRITICAL_FINDING', 'THREAT_DETECTED'],
        additionalEmails: ['secops@frontend-test.com'],
      }),
    });
    const patchSetRes = await updateAlertSettings(patchSetReq);
    const patchSetJson = await patchSetRes.json();
    assert.equal(patchSetRes.status, 200);
    assert.equal(patchSetJson.data.minRiskScore, 75);
    assert.deepEqual(patchSetJson.data.additionalEmails, ['secops@frontend-test.com']);

    // 6c. GET /api/org/members
    const memReq = new NextRequest('http://localhost:3000/api/org/members', {
      headers: { cookie: ownerCookie },
    });
    const memRes = await getMembers(memReq);
    const memJson = await memRes.json();
    assert.equal(memRes.status, 200);
    assert.ok(Array.isArray(memJson.data));
    assert.equal(memJson.data.length >= 1, true);
    assert.equal(memJson.data[0].role, 'OWNER');
  });

  it('7. Executive Summary Report API Contract', async () => {
    const execReq = new NextRequest('http://localhost:3000/api/reports/executive-summary', {
      headers: { cookie: ownerCookie },
    });
    const execRes = await getExecutiveSummary(execReq);
    const execJson = await execRes.json();
    assert.equal(execRes.status, 200);
    assert.ok(execJson.data.executiveSummary);
    assert.ok(execJson.data.overallPosture);
    assert.ok(Array.isArray(execJson.data.priorityActions));
  });

  it('8. VIEWER Role Permission Denials (403)', async () => {
    // Create a VIEWER user in this organization
    viewerUserId = 'user_fe_viewer';
    const viewerToken = createSessionToken({
      userId: viewerUserId,
      organizationId: orgId,
      email: 'viewer@frontend-test.com',
      role: 'VIEWER',
    });
    viewerCookie = `pliora_session=${viewerToken}`;

    memoryStore.users.set(viewerUserId, {
      _id: viewerUserId,
      id: viewerUserId,
      name: 'Auditor Viewer',
      email: 'viewer@frontend-test.com',
      passwordHash: 'dummy',
      globalRole: 'USER',
      activeOrganizationId: orgId,
      organizationMemberships: [
        {
          organizationId: orgId,
          role: 'VIEWER',
          joinedAt: new Date(),
        },
      ],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    // 8a. VIEWER cannot mutate findings
    const denyFinding = new NextRequest('http://localhost:3000/api/findings/f_fe_test_01', {
      method: 'PATCH',
      headers: { cookie: viewerCookie },
      body: JSON.stringify({ status: 'RESOLVED' }),
    });
    const dfRes = await updateFindingStatus(denyFinding, { params: { id: 'f_fe_test_01' } } as any);
    assert.equal(dfRes.status, 403, 'VIEWER role must receive 403 on finding mutation');

    // 8b. VIEWER cannot update alert settings
    const denySettings = new NextRequest('http://localhost:3000/api/org/alert-settings', {
      method: 'PATCH',
      headers: { cookie: viewerCookie },
      body: JSON.stringify({ minRiskScore: 50 }),
    });
    const dsRes = await updateAlertSettings(denySettings);
    assert.equal(dsRes.status, 403, 'VIEWER role must receive 403 on alert settings update');

    // 8c. VIEWER cannot trigger threat sweeps
    const denyThreatScan = new NextRequest('http://localhost:3000/api/threats/scan', {
      method: 'POST',
      headers: { cookie: viewerCookie },
    });
    const dtRes = await triggerThreatScan(denyThreatScan);
    assert.equal(dtRes.status, 403, 'VIEWER role must receive 403 on threat scan trigger');
  });

  it('9. Real-Time Free Perimeter Assessment Engine API', async () => {
    // 9a. Rejects missing domain
    const missingDomainReq = new NextRequest('http://localhost:3000/api/free-assessment', {
      method: 'POST',
      body: JSON.stringify({}),
    });
    const mdRes = await freeAssessment(missingDomainReq);
    assert.equal(mdRes.status, 400);
    const mdJson = await mdRes.json();
    assert.equal(mdJson.success, false);

    // 9b. Rejects invalid domain format
    const invalidDomainReq = new NextRequest('http://localhost:3000/api/free-assessment', {
      method: 'POST',
      body: JSON.stringify({ domain: 'invalid domain with spaces!!' }),
    });
    const idRes = await freeAssessment(invalidDomainReq);
    assert.equal(idRes.status, 400);

    // 9c. Rejects localhost / SSRF loopback domains
    const ssrfReq = new NextRequest('http://localhost:3000/api/free-assessment', {
      method: 'POST',
      body: JSON.stringify({ domain: 'localhost' }),
    });
    const ssrfRes = await freeAssessment(ssrfReq);
    assert.equal(ssrfRes.status, 400);

    // 9d. Live test with a real public domain
    const liveReq = new NextRequest('http://localhost:3000/api/free-assessment', {
      method: 'POST',
      body: JSON.stringify({ domain: 'innovaterax.in' }),
    });
    const liveRes = await freeAssessment(liveReq);
    assert.equal(liveRes.status, 200, 'Live assessment should return 200');
    const liveJson = await liveRes.json();
    assert.equal(liveJson.success, true);
    assert.equal(liveJson.domain, 'innovaterax.in');
    assert.ok(liveJson.ip, 'Must resolve an IP');
    assert.ok(liveJson.tls, 'Must contain TLS data');
    assert.ok(liveJson.tls.issuer, 'Must identify TLS issuer');
    assert.ok(typeof liveJson.securityPosture === 'number', 'Must calculate securityPosture');
    assert.ok(['A', 'B', 'C', 'D', 'F'].includes(liveJson.grade), 'Must assign letter grade');
    assert.ok(Array.isArray(liveJson.findings), 'Must return findings array');

    // 9e. Guarantee NO fake mock staging/psycopg2 findings exist
    for (const f of liveJson.findings) {
      assert.ok(!f.evidence.includes('psycopg2.connect'), 'Never return fake psycopg2 mock evidence');
      assert.ok(!f.asset.includes('staging.innovaterax.in'), 'Never return fake staging server finding');
    }
  });
});

