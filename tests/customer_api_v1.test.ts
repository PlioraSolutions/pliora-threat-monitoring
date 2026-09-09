import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { NextRequest } from 'next/server';
import { memoryStore } from '../src/lib/store';
import { apiKeyRateLimiter } from '../src/lib/auth/apiKeyAuth';
import { GET as getFindingsV1 } from '../src/app/api/v1/findings/route';
import { GET as getThreatsV1 } from '../src/app/api/v1/threats/route';
import { GET as getAssetsV1 } from '../src/app/api/v1/assets/route';
import { GET as getRiskScoreV1 } from '../src/app/api/v1/risk-score/route';

describe('Customer-Facing API v1 (§A.5)', () => {
  const orgAlphaId = 'org_v1_alpha';
  const orgBetaId = 'org_v1_beta';

  const rawKeyAlpha = 'plk_live_alpha_11112222333344445555';
  const keyAlphaHash = crypto.createHash('sha256').update(rawKeyAlpha).digest('hex');

  const rawKeyBeta = 'plk_live_beta_99998888777766665555';
  const keyBetaHash = crypto.createHash('sha256').update(rawKeyBeta).digest('hex');

  const rawKeyRevoked = 'plk_live_revoked_00001111222233334444';
  const keyRevokedHash = crypto.createHash('sha256').update(rawKeyRevoked).digest('hex');

  it('Setup: Initialize Orgs, API Keys, Findings, Threats, and Assets', async () => {
    // 1. Orgs
    memoryStore.organizations.set(orgAlphaId, {
      _id: orgAlphaId,
      id: orgAlphaId,
      name: 'Alpha Corp',
      plan: 'ENTERPRISE',
      createdAt: new Date(),
    });

    memoryStore.organizations.set(orgBetaId, {
      _id: orgBetaId,
      id: orgBetaId,
      name: 'Beta Corp',
      plan: 'PRO',
      createdAt: new Date(),
    });

    // 2. API Keys
    const keyAlphaRecord = {
      _id: 'key_alpha_01',
      id: 'key_alpha_01',
      organizationId: orgAlphaId,
      hashedKey: keyAlphaHash,
      keyHash: keyAlphaHash,
      keyPrefix: 'plk_live_alpha_1111',
      name: 'Alpha Production CI/CD',
      active: true,
      role: 'READONLY',
      createdAt: new Date(),
    };
    memoryStore.apiKeys.set(keyAlphaHash, keyAlphaRecord);
    memoryStore.apiKeys.set('key_alpha_01', keyAlphaRecord);

    const keyBetaRecord = {
      _id: 'key_beta_01',
      id: 'key_beta_01',
      organizationId: orgBetaId,
      hashedKey: keyBetaHash,
      keyHash: keyBetaHash,
      keyPrefix: 'plk_live_beta_9999',
      name: 'Beta Integration',
      active: true,
      role: 'READONLY',
      createdAt: new Date(),
    };
    memoryStore.apiKeys.set(keyBetaHash, keyBetaRecord);
    memoryStore.apiKeys.set('key_beta_01', keyBetaRecord);

    const keyRevokedRecord = {
      _id: 'key_revoked_01',
      id: 'key_revoked_01',
      organizationId: orgAlphaId,
      hashedKey: keyRevokedHash,
      keyHash: keyRevokedHash,
      keyPrefix: 'plk_live_revoked_0000',
      name: 'Revoked Key',
      active: false,
      role: 'READONLY',
      createdAt: new Date(),
    };
    memoryStore.apiKeys.set(keyRevokedHash, keyRevokedRecord);
    memoryStore.apiKeys.set('key_revoked_01', keyRevokedRecord);

    // 3. Findings
    memoryStore.findings.set('f_alpha_01', {
      _id: 'f_alpha_01',
      organizationId: orgAlphaId,
      title: 'Alpha Critical Heartbleed Exposure',
      findingCode: 'TLS-HEARTBLEED',
      severity: 'CRITICAL',
      confidence: 'CONFIRMED',
      status: 'OPEN',
      category: 'TLS',
      riskScore: 90,
      createdAt: new Date(),
    });
    memoryStore.findings.set('f_alpha_02', {
      _id: 'f_alpha_02',
      organizationId: orgAlphaId,
      title: 'Alpha Medium Missing CSP',
      findingCode: 'SEC-HEADER-CSP-MISSING',
      severity: 'MEDIUM',
      confidence: 'CONFIRMED',
      status: 'OPEN',
      category: 'HYGIENE',
      riskScore: 40,
      createdAt: new Date(),
    });

    memoryStore.findings.set('f_beta_01', {
      _id: 'f_beta_01',
      organizationId: orgBetaId,
      title: 'Beta High Database Exposure',
      findingCode: 'PORT-EXPOSED-REDIS',
      severity: 'HIGH',
      confidence: 'HIGH',
      status: 'OPEN',
      category: 'DATABASE_MISCONFIG',
      riskScore: 75,
      createdAt: new Date(),
    });

    // 4. Threats
    memoryStore.threats.set('t_alpha_01', {
      _id: 't_alpha_01',
      organizationId: orgAlphaId,
      indicator: 'alpha-login-portal.com',
      relatedRootDomain: 'alpha.com',
      source: 'TYPOSQUAT_PERMUTATION',
      confidence: 'HIGH',
      corroborationScore: 85,
      status: 'OPEN',
      firstSeen: new Date(),
      lastSeen: new Date(),
      dedupKey: 'threat_alpha_01',
      createdAt: new Date(),
    });

    memoryStore.threats.set('t_beta_01', {
      _id: 't_beta_01',
      organizationId: orgBetaId,
      indicator: 'beta-verify-account.net',
      relatedRootDomain: 'beta.io',
      source: 'CT_LOG',
      confidence: 'CONFIRMED',
      corroborationScore: 95,
      status: 'OPEN',
      firstSeen: new Date(),
      lastSeen: new Date(),
      dedupKey: 'threat_beta_01',
      createdAt: new Date(),
    });

    // 5. Assets
    memoryStore.assets.set('asset_alpha_01', {
      _id: 'asset_alpha_01',
      organizationId: orgAlphaId,
      rootDomain: 'alpha.com',
      fqdn: 'api.alpha.com',
      type: 'SUBDOMAIN',
      importance: 'CRITICAL',
      verificationStatus: 'VERIFIED',
      verificationToken: 'token_alpha_1',
      createdAt: new Date(),
    });

    memoryStore.assets.set('asset_beta_01', {
      _id: 'asset_beta_01',
      organizationId: orgBetaId,
      rootDomain: 'beta.io',
      fqdn: 'beta.io',
      type: 'ROOT_DOMAIN',
      importance: 'HIGH',
      verificationStatus: 'VERIFIED',
      verificationToken: 'token_beta_1',
      createdAt: new Date(),
    });
  });

  it('Authentication: Rejects requests missing or having invalid Authorization header', async () => {
    // Missing header
    const req1 = new NextRequest('http://localhost:3000/api/v1/findings');
    const res1 = await getFindingsV1(req1);
    assert.strictEqual(res1.status, 401);
    const json1 = await res1.json();
    assert.strictEqual(json1.success, false);
    assert.strictEqual(json1.error.code, 'UNAUTHORIZED');

    // Invalid format (not Bearer)
    const req2 = new NextRequest('http://localhost:3000/api/v1/findings', {
      headers: { Authorization: 'Basic dXNlcjpwYXNz' },
    });
    const res2 = await getFindingsV1(req2);
    assert.strictEqual(res2.status, 401);

    // Non-existent key
    const req3 = new NextRequest('http://localhost:3000/api/v1/findings', {
      headers: { Authorization: 'Bearer plk_live_unknown_key_000000000000' },
    });
    const res3 = await getFindingsV1(req3);
    assert.strictEqual(res3.status, 401);

    // Revoked / Inactive key
    const req4 = new NextRequest('http://localhost:3000/api/v1/findings', {
      headers: { Authorization: `Bearer ${rawKeyRevoked}` },
    });
    const res4 = await getFindingsV1(req4);
    assert.strictEqual(res4.status, 401);
    const json4 = await res4.json();
    assert.strictEqual(json4.error.code, 'API_KEY_REVOKED');
  });

  it('Tenant Isolation (§A.5): Key for Org A cannot see Org B findings, threats, or assets', async () => {
    // Findings: Org A
    const reqFindA = new NextRequest('http://localhost:3000/api/v1/findings', {
      headers: { Authorization: `Bearer ${rawKeyAlpha}` },
    });
    const resFindA = await getFindingsV1(reqFindA);
    assert.strictEqual(resFindA.status, 200);
    const jsonFindA = await resFindA.json();
    assert.strictEqual(jsonFindA.success, true);
    assert.strictEqual(jsonFindA.meta.total, 2);
    assert.ok(jsonFindA.data.every((f: any) => f.organizationId === orgAlphaId));
    assert.ok(!jsonFindA.data.some((f: any) => f.organizationId === orgBetaId));

    // Threats: Org A
    const reqThreatA = new NextRequest('http://localhost:3000/api/v1/threats', {
      headers: { Authorization: `Bearer ${rawKeyAlpha}` },
    });
    const resThreatA = await getThreatsV1(reqThreatA);
    assert.strictEqual(resThreatA.status, 200);
    const jsonThreatA = await resThreatA.json();
    assert.strictEqual(jsonThreatA.success, true);
    assert.strictEqual(jsonThreatA.meta.total, 1);
    assert.strictEqual(jsonThreatA.data[0].indicator, 'alpha-login-portal.com');
    assert.ok(!jsonThreatA.data.some((t: any) => t.indicator.includes('beta')));

    // Assets: Org A
    const reqAssetA = new NextRequest('http://localhost:3000/api/v1/assets', {
      headers: { Authorization: `Bearer ${rawKeyAlpha}` },
    });
    const resAssetA = await getAssetsV1(reqAssetA);
    assert.strictEqual(resAssetA.status, 200);
    const jsonAssetA = await resAssetA.json();
    assert.strictEqual(jsonAssetA.success, true);
    assert.strictEqual(jsonAssetA.meta.total, 1);
    assert.strictEqual(jsonAssetA.data[0].fqdn, 'api.alpha.com');

    // Threats: Org B
    const reqThreatB = new NextRequest('http://localhost:3000/api/v1/threats', {
      headers: { Authorization: `Bearer ${rawKeyBeta}` },
    });
    const resThreatB = await getThreatsV1(reqThreatB);
    assert.strictEqual(resThreatB.status, 200);
    const jsonThreatB = await resThreatB.json();
    assert.strictEqual(jsonThreatB.success, true);
    assert.strictEqual(jsonThreatB.meta.total, 1);
    assert.strictEqual(jsonThreatB.data[0].indicator, 'beta-verify-account.net');
    assert.ok(!jsonThreatB.data.some((t: any) => t.indicator.includes('alpha')));
  });

  it('GET /api/v1/risk-score: Returns organization-specific posture score & envelope', async () => {
    const req = new NextRequest('http://localhost:3000/api/v1/risk-score', {
      headers: { Authorization: `Bearer ${rawKeyAlpha}` },
    });
    const res = await getRiskScoreV1(req);
    assert.strictEqual(res.status, 200);
    const json = await res.json();
    assert.strictEqual(json.success, true);
    assert.strictEqual(typeof json.data.score, 'number');
    assert.strictEqual(typeof json.data.securityPosture, 'number');
    assert.ok(['A', 'B', 'C', 'D', 'F'].includes(json.data.grade));
    assert.ok(json.data.factors);
    assert.strictEqual(json.data.factors.criticalCount, 1);
    assert.strictEqual(json.data.factors.mediumCount, 1);
  });

  it('Filtering & Sorting: GET /api/v1/findings respects query parameters', async () => {
    const req = new NextRequest('http://localhost:3000/api/v1/findings?severity=CRITICAL', {
      headers: { Authorization: `Bearer ${rawKeyAlpha}` },
    });
    const res = await getFindingsV1(req);
    assert.strictEqual(res.status, 200);
    const json = await res.json();
    assert.strictEqual(json.success, true);
    assert.strictEqual(json.data.length, 1);
    assert.strictEqual(json.data[0].severity, 'CRITICAL');
  });

  it('Rate Limiting (§A.5): Enforces 60 requests per minute with 429 and Retry-After', async () => {
    const rateLimitKey = 'plk_live_ratelimit_test_key_xyz';
    const rateLimitHash = crypto.createHash('sha256').update(rateLimitKey).digest('hex');

    const rateLimitRecord = {
      _id: 'key_ratelimit_01',
      id: 'key_ratelimit_01',
      organizationId: orgAlphaId,
      hashedKey: rateLimitHash,
      keyHash: rateLimitHash,
      keyPrefix: 'plk_live_ratelimit_test',
      name: 'Rate Limit Test Key',
      active: true,
      role: 'READONLY',
      createdAt: new Date(),
    };
    memoryStore.apiKeys.set(rateLimitHash, rateLimitRecord);
    memoryStore.apiKeys.set('key_ratelimit_01', rateLimitRecord);

    // Make 60 requests within the window
    for (let i = 0; i < 60; i++) {
      const check = apiKeyRateLimiter.checkRateLimit(rateLimitRecord._id);
      assert.strictEqual(check.allowed, true, `Request ${i + 1} should be allowed`);
    }

    // 61st request should be blocked
    const overLimit = apiKeyRateLimiter.checkRateLimit(rateLimitRecord._id);
    assert.strictEqual(overLimit.allowed, false, '61st request must be rate limited');
    assert.strictEqual(overLimit.remaining, 0);
    assert.ok(overLimit.resetSeconds > 0);

    // Call actual route with over-limit key to verify HTTP 429 response
    const req = new NextRequest('http://localhost:3000/api/v1/findings', {
      headers: { Authorization: `Bearer ${rateLimitKey}` },
    });
    const res = await getFindingsV1(req);
    assert.strictEqual(res.status, 429, 'Must return HTTP 429 Too Many Requests');
    assert.ok(res.headers.get('Retry-After'));
    assert.strictEqual(res.headers.get('X-RateLimit-Remaining'), '0');

    const json = await res.json();
    assert.strictEqual(json.success, false);
    assert.strictEqual(json.error.code, 'RATE_LIMIT_EXCEEDED');
  });
});
