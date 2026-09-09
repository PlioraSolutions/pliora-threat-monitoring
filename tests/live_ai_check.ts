import assert from 'assert';
import { createSessionToken } from '../src/lib/auth';

const BASE_URL = 'http://localhost:3000';

async function runLiveAiCheck() {
  console.log('Testing Grounded AI Security Analyst endpoints against live dev server...\n');

  const orgId = `org-live-ai-${Date.now()}`;
  const adminCookie = createSessionToken({
    userId: 'user-live-ai-admin',
    email: 'admin@live-ai.test',
    organizationId: orgId,
    role: 'ADMIN',
  });
  const crossCookie = createSessionToken({
    userId: 'user-live-ai-cross',
    email: 'attacker@other-org.test',
    organizationId: 'other-org-xyz',
    role: 'ADMIN',
  });

  // 1. Register & verify asset dns.google
  const targetDomain = 'dns.google';
  const assetRes = await fetch(`${BASE_URL}/api/assets`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: `pliora_session=${adminCookie}` },
    body: JSON.stringify({ domain: targetDomain, importance: 'HIGH' }),
  });
  const assetJson = await assetRes.json();
  const assetId = assetJson.data?._id || assetJson.data?.id;

  await fetch(`${BASE_URL}/api/assets/${assetId}/verify`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: `pliora_session=${adminCookie}`,
      'x-test-verification': 'true',
    },
    body: JSON.stringify({ bypassVerification: true }),
  });
  console.log(`✅ 1. Registered and verified test asset ${targetDomain}`);

  // 2. Trigger scan to produce real findings
  const scanRes = await fetch(`${BASE_URL}/api/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: `pliora_session=${adminCookie}` },
    body: JSON.stringify({ assetId, scanType: 'EXPOSURE' }),
  });
  assert.strictEqual(scanRes.status, 202);
  console.log('✅ 2. Triggered background exposure scan on live target');

  // Poll for findings produced by scan
  let findingsJson: any = { data: [] };
  for (let attempt = 0; attempt < 12; attempt++) {
    await new Promise((r) => setTimeout(r, 600));
    const findingsRes = await fetch(`${BASE_URL}/api/findings`, {
      headers: { Cookie: `pliora_session=${adminCookie}` },
    });
    findingsJson = await findingsRes.json();
    if (findingsJson.data && findingsJson.data.length > 0) break;
  }

  assert.ok(findingsJson.data && findingsJson.data.length > 0, 'Should have findings from scan');
  const sampleFinding = findingsJson.data[0];
  const findingId = sampleFinding._id || sampleFinding.id;
  console.log(`✅ 3. Retrieved ${findingsJson.data.length} findings (Sample: ${sampleFinding.findingCode})`);

  // 3. GET /api/findings/:id/explain
  const explainRes = await fetch(`${BASE_URL}/api/findings/${findingId}/explain`, {
    headers: { Cookie: `pliora_session=${adminCookie}` },
  });
  assert.strictEqual(explainRes.status, 200);
  const explainJson = await explainRes.json();
  assert.strictEqual(explainJson.success, true);
  assert.ok(explainJson.data.explanation, 'Must have explanation');
  assert.ok(explainJson.data.businessImpact, 'Must have business impact');
  assert.ok(explainJson.data.confidenceCaveat, 'Must have confidence caveat');
  assert.ok(explainJson.data.remediationSteps.length > 0, 'Must have remediation steps');
  console.log(`✅ 4. GET /api/findings/:id/explain succeeded with grounded response:\n      Caveat: "${explainJson.data.confidenceCaveat}"`);

  // 4. Second request hits cache
  const cachedRes = await fetch(`${BASE_URL}/api/findings/${findingId}/explain`, {
    headers: { Cookie: `pliora_session=${adminCookie}` },
  });
  assert.strictEqual(cachedRes.status, 200);
  const cachedJson = await cachedRes.json();
  assert.strictEqual(cachedJson.data.cacheHit, true);
  console.log('✅ 5. Repeated GET /api/findings/:id/explain returned instantly from cache (cacheHit: true)');

  // 5. Cross-tenant defense: access from another tenant returns 404
  const crossRes = await fetch(`${BASE_URL}/api/findings/${findingId}/explain`, {
    headers: { Cookie: `pliora_session=${crossCookie}` },
  });
  assert.strictEqual(crossRes.status, 404);
  console.log('✅ 6. Cross-tenant explanation request rejected with HTTP 404 (anti-enumeration)');

  // 6. Trigger threat scan & test GET /api/threats/:id/explain
  const threatScanRes = await fetch(`${BASE_URL}/api/threats/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: `pliora_session=${adminCookie}` },
    body: JSON.stringify({ domain: targetDomain }),
  });
  assert.strictEqual(threatScanRes.status, 200);

  const threatsRes = await fetch(`${BASE_URL}/api/threats`, {
    headers: { Cookie: `pliora_session=${adminCookie}` },
  });
  const threatsJson = await threatsRes.json();
  assert.ok(threatsJson.data && threatsJson.data.length > 0, 'Should have threats');
  const sampleThreat = threatsJson.data[0];
  const threatId = sampleThreat._id || sampleThreat.id;

  const threatExplainRes = await fetch(`${BASE_URL}/api/threats/${threatId}/explain`, {
    headers: { Cookie: `pliora_session=${adminCookie}` },
  });
  assert.strictEqual(threatExplainRes.status, 200);
  const threatExplainJson = await threatExplainRes.json();
  assert.ok(threatExplainJson.data.explanation);
  assert.ok(threatExplainJson.data.confidenceCaveat);
  console.log(`✅ 7. GET /api/threats/:id/explain succeeded for look-alike threat "${sampleThreat.indicator}"`);

  // 7. GET /api/reports/executive-summary
  const execRes = await fetch(`${BASE_URL}/api/reports/executive-summary`, {
    headers: { Cookie: `pliora_session=${adminCookie}` },
  });
  assert.strictEqual(execRes.status, 200);
  const execJson = await execRes.json();
  assert.strictEqual(execJson.success, true);
  assert.ok(execJson.data.executiveSummary, 'Must have executive summary');
  assert.ok(execJson.data.overallPosture, 'Must have overall posture');
  assert.ok(Array.isArray(execJson.data.keyRisks), 'Must have key risks array');
  assert.ok(Array.isArray(execJson.data.priorityActions), 'Must have priority actions');
  console.log(`✅ 8. GET /api/reports/executive-summary returned posture: ${execJson.data.overallPosture} with ${execJson.data.keyRisks.length} key risks`);

  console.log('\n🎉 ALL GROUNDED AI ANALYST ENDPOINTS VERIFIED OVER HTTP!');
}

runLiveAiCheck().catch((err) => {
  console.error('Live check failed:', err);
  process.exit(1);
});
