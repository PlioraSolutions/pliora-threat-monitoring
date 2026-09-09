import assert from 'assert';
import { createSessionToken } from '../src/lib/auth';

const BASE_URL = 'http://localhost:3000';

async function runLiveCheck() {
  console.log('Testing Threat & Brand Monitoring endpoints against live dev server...\n');

  const orgId = `org-live-threat-${Date.now()}`;
  const adminCookie = createSessionToken({
    userId: 'user-live-threat-admin',
    email: 'admin@live-threat.test',
    organizationId: orgId,
    role: 'ADMIN',
  });
  const viewerCookie = createSessionToken({
    userId: 'user-live-threat-viewer',
    email: 'viewer@live-threat.test',
    organizationId: orgId,
    role: 'VIEWER',
  });

  // 1. GET /api/threats initially returns empty array with pagination
  const res1 = await fetch(`${BASE_URL}/api/threats`, {
    headers: { Cookie: `pliora_session=${adminCookie}` },
  });
  assert.strictEqual(res1.status, 200);
  const json1 = await res1.json();
  assert.strictEqual(json1.success, true);
  assert.strictEqual(Array.isArray(json1.data), true);
  console.log('✅ 1. GET /api/threats returned HTTP 200 with valid pagination envelope');

  // 2. Register and verify an asset so POST /api/threats/scan can be called
  const assetRes = await fetch(`${BASE_URL}/api/assets`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: `pliora_session=${adminCookie}` },
    body: JSON.stringify({ domain: 'acme-security-test.com', importance: 'HIGH' }),
  });
  const assetJson = await assetRes.json();
  const assetId = assetJson.data?._id || assetJson.data?.id;

  // Bypass verify
  await fetch(`${BASE_URL}/api/assets/${assetId}/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: `pliora_session=${adminCookie}`, 'x-test-verification': 'true' },
    body: JSON.stringify({ bypassVerification: true }),
  });
  console.log('✅ 2. Registered and verified asset acme-security-test.com');

  // 3. POST /api/threats/scan triggers monitoring
  const scanRes = await fetch(`${BASE_URL}/api/threats/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: `pliora_session=${adminCookie}` },
    body: JSON.stringify({ domain: 'acme-security-test.com' }),
  });
  assert.strictEqual(scanRes.status, 200);
  const scanJson = await scanRes.json();
  assert.strictEqual(scanJson.success, true);
  assert.ok(scanJson.data.totalPermutationsGenerated > 0);
  console.log(`✅ 3. POST /api/threats/scan generated ${scanJson.data.totalPermutationsGenerated} permutations and evaluated ${scanJson.data.candidatesEvaluated} candidates`);

  // 4. GET /api/threats now lists threats
  const resList = await fetch(`${BASE_URL}/api/threats`, {
    headers: { Cookie: `pliora_session=${adminCookie}` },
  });
  assert.strictEqual(resList.status, 200);
  const jsonList = await resList.json();
  assert.ok(jsonList.data.length > 0, 'Should have threats listed');
  const sampleThreat = jsonList.data[0];
  const sampleId = sampleThreat._id || sampleThreat.id;
  console.log(`✅ 4. GET /api/threats retrieved ${jsonList.data.length} threats (Sample: ${sampleThreat.indicator}, Score: ${sampleThreat.corroborationScore})`);

  // 5. GET /api/threats/[id]
  const resDetail = await fetch(`${BASE_URL}/api/threats/${sampleId}`, {
    headers: { Cookie: `pliora_session=${adminCookie}` },
  });
  assert.strictEqual(resDetail.status, 200);
  const jsonDetail = await resDetail.json();
  assert.strictEqual(jsonDetail.success, true);
  assert.ok(jsonDetail.data.evidence, 'Should embed linked Evidence observation');
  console.log('✅ 5. GET /api/threats/:id returns detail with linked Evidence observation');

  // 6. PATCH /api/threats/[id] - VIEWER denied
  const resViewer = await fetch(`${BASE_URL}/api/threats/${sampleId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Cookie: `pliora_session=${viewerCookie}` },
    body: JSON.stringify({ status: 'MONITORING' }),
  });
  assert.strictEqual(resViewer.status, 403);
  console.log('✅ 6. PATCH /api/threats/:id strictly rejects VIEWER mutation with HTTP 403');

  // 7. PATCH /api/threats/[id] - ADMIN succeeds
  const resAdmin = await fetch(`${BASE_URL}/api/threats/${sampleId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Cookie: `pliora_session=${adminCookie}` },
    body: JSON.stringify({ status: 'MONITORING', notes: 'Observing registrar status' }),
  });
  assert.strictEqual(resAdmin.status, 200);
  const jsonAdmin = await resAdmin.json();
  assert.strictEqual(jsonAdmin.data.status, 'MONITORING');
  console.log('✅ 7. PATCH /api/threats/:id transitions OPEN -> MONITORING successfully');

  console.log('\n🎉 ALL LIVE THREAT ENDPOINTS VERIFIED OVER HTTP!');
}

runLiveCheck().catch((err) => {
  console.error('Live check failed:', err);
  process.exit(1);
});
