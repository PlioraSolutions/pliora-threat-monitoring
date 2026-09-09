import { NextRequest } from 'next/server';
import { memoryStore } from '../src/lib/store';
import { createSessionToken } from '../src/lib/auth';
import {
  normalizeDiscoveredHostname,
  isValidHostname,
  upsertDiscoveredAsset,
} from '../src/lib/discovery/upsertAsset';
import {
  queryCertificateTransparency,
  clearCtCache,
} from '../src/lib/discovery/ctLog';
import {
  enumerateDnsPermutations,
  DEFAULT_SUBDOMAIN_WORDLIST,
} from '../src/lib/discovery/dnsPermutation';
import { runPassiveDiscovery } from '../src/lib/discovery/engine';
import { processScanJob } from '../src/workers/scanProcessor';
import { deriveExposure } from '../src/lib/risk/exposure';
import { POST as verifyAssetRoute } from '../src/app/api/assets/[id]/verify/route';
import { POST as discoverAssetRoute } from '../src/app/api/assets/[id]/discover/route';
import { GET as getAssetsRoute, POST as postAssetRoute } from '../src/app/api/assets/route';

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

async function runDiscoveryEngineTests() {
  console.log('🔍 Running Option 4: Passive Asset Discovery Engine Tests...\n');

  // =========================================================================
  // Test Suite 1: Hostname Normalization & RFC 1123 Validation
  // =========================================================================
  console.log('--- Test Suite 1: Normalization & RFC 1123 Validation ---');

  assert(
    normalizeDiscoveredHostname('*.Staging.ACME.com.') === 'staging.acme.com',
    'normalizeDiscoveredHostname strips leading wildcard, converts to lowercase, and strips trailing dot'
  );
  assert(
    normalizeDiscoveredHostname('  api.prod.example.com  ') === 'api.prod.example.com',
    'normalizeDiscoveredHostname trims whitespace'
  );
  assert(
    normalizeDiscoveredHostname('*.sub.*.invalid.com') === 'sub.*.invalid.com',
    'normalizeDiscoveredHostname only strips leading *.'
  );

  assert(isValidHostname('acme.com') === true, 'isValidHostname accepts valid apex domain');
  assert(isValidHostname('api.staging.acme.com') === true, 'isValidHostname accepts valid subdomain');
  assert(isValidHostname('a-b-c.123.org') === true, 'isValidHostname accepts hyphens and numbers');
  assert(isValidHostname('invalid_char.com') === false, 'isValidHostname rejects underscores in labels');
  assert(isValidHostname('localhost') === false, 'isValidHostname rejects single label hostnames');
  assert(isValidHostname('sub..acme.com') === false, 'isValidHostname rejects consecutive dots');
  assert(isValidHostname('-badlabel.com') === false, 'isValidHostname rejects label starting with hyphen');

  // =========================================================================
  // Test Suite 2: Verification Inheritance Rule (§1)
  // =========================================================================
  console.log('\n--- Test Suite 2: Verification Inheritance Rule ---');

  const orgId = 'org-disc-test-01';
  memoryStore.assets.clear();
  memoryStore.auditLogs = [];

  // Scenario 2.1: Discovered subdomain under VERIFIED parent inherits verification
  const resInherited = await upsertDiscoveredAsset({
    organizationId: orgId,
    rootDomain: 'acme.com',
    fqdn: 'api.acme.com',
    method: 'CT_LOG',
    parentVerified: true,
  });

  assert(resInherited !== null, 'upsertDiscoveredAsset creates asset');
  assert(resInherited?.action === 'CREATED', 'First discovery action is CREATED');
  assert(
    resInherited?.asset.verificationStatus === 'INHERITED_VERIFIED',
    'Subdomain under verified parent receives INHERITED_VERIFIED status'
  );
  assert(
    resInherited?.asset.verifiedAt instanceof Date,
    'INHERITED_VERIFIED asset has verifiedAt timestamp populated'
  );

  // Scenario 2.2: Discovered subdomain under UNVERIFIED parent remains PENDING
  const resPending = await upsertDiscoveredAsset({
    organizationId: orgId,
    rootDomain: 'unverified.io',
    fqdn: 'api.unverified.io',
    method: 'DNS_PERMUTATION',
    parentVerified: false,
  });

  assert(
    resPending?.asset.verificationStatus === 'PENDING',
    'Subdomain under unverified parent remains PENDING'
  );
  assert(
    resPending?.asset.verifiedAt === undefined,
    'PENDING asset does not have verifiedAt timestamp'
  );

  // Scenario 2.3: Cross-domain discovery (different apex) remains PENDING even if caller claims verified
  const resCrossDomain = await upsertDiscoveredAsset({
    organizationId: orgId,
    rootDomain: 'acme.com',
    fqdn: 'thirdpartyservice.net',
    method: 'CT_LOG',
    parentVerified: true,
  });

  assert(
    resCrossDomain?.asset.verificationStatus === 'PENDING',
    'Cross-domain discovery (different apex) remains PENDING even if parent domain is verified'
  );

  // =========================================================================
  // Test Suite 3: Canonical Asset Upsert, Merge & Multi-Provenance (§3)
  // =========================================================================
  console.log('\n--- Test Suite 3: Canonical Upsert & Multi-Provenance Tracking ---');

  // Scenario 3.1: Discover api.acme.com again via DNS_PERMUTATION -> merges provenance
  const originalFirstSeen = resInherited!.asset.firstSeen;
  // Sleep a tiny tick to verify lastSeen updates
  await new Promise((r) => setTimeout(r, 10));

  const resMerged = await upsertDiscoveredAsset({
    organizationId: orgId,
    rootDomain: 'acme.com',
    fqdn: 'api.acme.com',
    method: 'DNS_PERMUTATION',
    parentVerified: true,
  });

  assert(resMerged?.isNew === false, 'Rediscovered asset isNew is false');
  assert(resMerged?.action === 'MERGED', 'Rediscovery with new method action is MERGED');
  assert(
    resMerged?.asset.discoveredVia.includes('CT_LOG') &&
      resMerged?.asset.discoveredVia.includes('DNS_PERMUTATION'),
    'discoveredVia array contains both CT_LOG and DNS_PERMUTATION'
  );
  assert(
    new Date(resMerged!.asset.firstSeen).getTime() === new Date(originalFirstSeen).getTime(),
    'Earliest firstSeen timestamp is preserved'
  );
  assert(
    new Date(resMerged!.asset.lastSeen).getTime() >= new Date(originalFirstSeen).getTime(),
    'lastSeen timestamp is updated to current discovery time'
  );

  // Scenario 3.2: Duplicate discovery with SAME method -> UNCHANGED
  const resUnchanged = await upsertDiscoveredAsset({
    organizationId: orgId,
    rootDomain: 'acme.com',
    fqdn: 'api.acme.com',
    method: 'CT_LOG',
    parentVerified: true,
  });

  assert(resUnchanged?.action === 'UNCHANGED', 'Rediscovery with existing method action is UNCHANGED');

  // Scenario 3.3: Never downgrade VERIFIED status
  // Manually set an asset to VERIFIED
  resInherited!.asset.verificationStatus = 'VERIFIED';
  const resNoDowngrade = await upsertDiscoveredAsset({
    organizationId: orgId,
    rootDomain: 'acme.com',
    fqdn: 'api.acme.com',
    method: 'DNS_PERMUTATION',
    parentVerified: false, // Parent claimed unverified now
  });

  assert(
    resNoDowngrade?.asset.verificationStatus === 'VERIFIED',
    'VERIFIED status is never downgraded to PENDING or INHERITED_VERIFIED'
  );

  // Scenario 3.4: Upgrade PENDING to INHERITED_VERIFIED on parent verification
  const resPendingUpgrade = await upsertDiscoveredAsset({
    organizationId: orgId,
    rootDomain: 'unverified.io',
    fqdn: 'api.unverified.io',
    method: 'CT_LOG',
    parentVerified: true, // Now parent is verified
  });

  assert(
    resPendingUpgrade?.asset.verificationStatus === 'INHERITED_VERIFIED',
    'Prior PENDING same-apex asset upgrades to INHERITED_VERIFIED once parent is verified'
  );

  // Scenario 3.5: AuditLog created on discovery
  const discAuditLog = memoryStore.auditLogs.find(
    (l) => l.action === 'ASSET_DISCOVERED' && l.details?.fqdn === 'api.acme.com'
  );
  assert(Boolean(discAuditLog), 'ASSET_DISCOVERED audit log created for discovered asset');
  assert(
    discAuditLog?.details?.method === 'CT_LOG',
    'AuditLog details record discovery method'
  );

  // =========================================================================
  // Test Suite 4: Certificate Transparency (CT) Log Query Client (§2)
  // =========================================================================
  console.log('\n--- Test Suite 4: Certificate Transparency Query Client ---');

  clearCtCache();

  // Test with invalid domain
  const invalidCt = await queryCertificateTransparency('not a valid domain!');
  assert(invalidCt.candidates.length === 0, 'Invalid root domain returns empty candidates');
  assert(Boolean(invalidCt.error), 'Invalid root domain returns error string');

  // Mock global fetch for deterministic CT-log parsing tests
  const originalFetch = global.fetch;
  try {
    const mockCrtShData = [
      {
        common_name: 'acme.com',
        name_value: 'acme.com\n*.staging.acme.com\nvpn.acme.com',
      },
      {
        common_name: 'api.acme.com',
        name_value: 'api.acme.com\nmalicious-unrelated.com\n*.corp.acme.com',
      },
    ];

    global.fetch = async (url: any, opts: any) => {
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify(mockCrtShData),
      } as any;
    };

    const ctResult = await queryCertificateTransparency('acme.com');

    assert(ctResult.candidates.includes('acme.com'), 'Parses apex domain from CT entries');
    assert(ctResult.candidates.includes('api.acme.com'), 'Parses common_name subdomain');
    assert(
      ctResult.candidates.includes('staging.acme.com'),
      'Strips *. wildcard and normalizes staging.acme.com'
    );
    assert(
      ctResult.candidates.includes('corp.acme.com'),
      'Strips *. wildcard and normalizes corp.acme.com'
    );
    assert(ctResult.candidates.includes('vpn.acme.com'), 'Parses vpn.acme.com from name_value');
    assert(
      !ctResult.candidates.includes('malicious-unrelated.com'),
      'Filters out domains that do not belong to target root domain apex'
    );
    assert(ctResult.cached === false, 'First request was not cached');

    // Test Caching: Second call should hit in-memory cache
    const cachedCtResult = await queryCertificateTransparency('acme.com');
    assert(cachedCtResult.cached === true, 'Subsequent call within 5 min returns cached: true');
    assert(
      cachedCtResult.candidates.length === ctResult.candidates.length,
      'Cached candidates list matches original'
    );

    // Test 502 / Error Response Resilience: Should not throw
    clearCtCache();
    global.fetch = async () => {
      return {
        ok: false,
        status: 502,
        text: async () => '502 Bad Gateway',
      } as any;
    };

    const failedCt = await queryCertificateTransparency('acme.com');
    assert(failedCt.candidates.length === 0, 'HTTP 502 returns empty candidate list without throwing');
    assert(Boolean(failedCt.error?.includes('502')), 'Error message reports upstream HTTP 502 status');

    // Test Timeout Resilience (AbortError)
    global.fetch = async (url: any, opts: any) => {
      const error: any = new Error('The user aborted a request.');
      error.name = 'AbortError';
      throw error;
    };

    const timeoutCt = await queryCertificateTransparency('acme.com');
    assert(timeoutCt.timedOut === true, 'AbortError correctly flagged as timedOut: true');
    assert(timeoutCt.candidates.length === 0, 'Timed-out query returns empty list without crashing');
  } finally {
    global.fetch = originalFetch;
  }

  // =========================================================================
  // Test Suite 5: DNS Permutation Enumeration (§4)
  // =========================================================================
  console.log('\n--- Test Suite 5: DNS Permutation Enumeration ---');

  assert(
    DEFAULT_SUBDOMAIN_WORDLIST.includes('api') &&
      DEFAULT_SUBDOMAIN_WORDLIST.includes('staging') &&
      DEFAULT_SUBDOMAIN_WORDLIST.includes('vpn'),
    'DEFAULT_SUBDOMAIN_WORDLIST contains high-value attack surface targets'
  );

  // Test invalid input
  const invalidDns = await enumerateDnsPermutations('invalid host');
  assert(invalidDns.candidates.length === 0, 'Invalid root domain returns empty candidates');

  // Test custom wordlist with throttled batch concurrency
  const customWordlist = ['test1', 'test2', 'test3'];
  const permResult = await enumerateDnsPermutations('example.com', {
    wordlist: customWordlist,
    concurrency: 2,
  });

  assert(permResult.totalTested === 3, 'Tested exactly the requested custom wordlist count');
  assert(Array.isArray(permResult.candidates), 'Returns array of resolving candidates');

  // =========================================================================
  // Test Suite 6: Scan Pipeline & Risk Score Verification Gate (§1, §2.3)
  // =========================================================================
  console.log('\n--- Test Suite 6: Scan Pipeline & Risk Score Verification Gate ---');

  // Exposure calculation with INHERITED_VERIFIED
  const expInherited = deriveExposure({
    fqdn: 'api.acme.com',
    type: 'SUBDOMAIN',
    verificationStatus: 'INHERITED_VERIFIED',
  });

  const expPending = deriveExposure({
    fqdn: 'api.acme.com',
    type: 'SUBDOMAIN',
    verificationStatus: 'PENDING',
  });

  assert(
    expInherited.reachabilityWeight === 1.0,
    'deriveExposure assigns full reachabilityWeight (1.0) to INHERITED_VERIFIED assets'
  );
  assert(
    expPending.reachabilityWeight === 0.7,
    'deriveExposure assigns reduced reachabilityWeight (0.7) to unverified PENDING assets'
  );
  assert(
    expInherited.exposureFactor > expPending.exposureFactor,
    'deriveExposure yields higher exposure factor for INHERITED_VERIFIED asset than PENDING asset'
  );

  // Scan processor verification gate test
  const testScanId1 = 'scan-inherited-pass';
  const testScanId2 = 'scan-pending-fail';

  const assetInherited = {
    _id: 'asset-inherited-01',
    organizationId: orgId,
    fqdn: 'api.acme.com',
    rootDomain: 'acme.com',
    type: 'SUBDOMAIN',
    importance: 'HIGH',
    verificationStatus: 'INHERITED_VERIFIED',
    ipAddresses: ['1.1.1.1'],
    save: async () => {},
  };

  const assetPending = {
    _id: 'asset-pending-02',
    organizationId: orgId,
    fqdn: 'unverified.acme.com',
    rootDomain: 'acme.com',
    type: 'SUBDOMAIN',
    importance: 'NORMAL',
    verificationStatus: 'PENDING',
    ipAddresses: [],
    save: async () => {},
  };

  memoryStore.assets.set(assetInherited._id, assetInherited);
  memoryStore.assets.set(assetPending._id, assetPending);

  const scanInherited = {
    _id: testScanId1,
    organizationId: orgId,
    assetId: assetInherited._id,
    scanType: 'DISCOVERY',
    status: 'PENDING',
    progress: 0,
    counters: { checksTotal: 0, checksCompleted: 0, findingsFound: 0 },
    save: async () => {},
  };

  const scanPending: any = {
    _id: testScanId2,
    organizationId: orgId,
    assetId: assetPending._id,
    scanType: 'EXPOSURE',
    status: 'PENDING',
    progress: 0,
    counters: { checksTotal: 0, checksCompleted: 0, findingsFound: 0 },
    save: async () => {},
  };

  memoryStore.scans.set(testScanId1, scanInherited);
  memoryStore.scans.set(testScanId2, scanPending);

  // Process PENDING asset scan -> must abort at Stage 1
  await processScanJob({
    scanId: testScanId2,
    organizationId: orgId,
    assetId: assetPending._id,
    scanType: 'EXPOSURE',
  });

  assert(scanPending.status === 'FAILED', 'Scan on PENDING asset is aborted at Stage 1');
  assert(
    scanPending.error?.includes('not verified'),
    'Scan error clarifies unverified status'
  );

  // =========================================================================
  // Test Suite 7: Unified Discovery Coordinator (runPassiveDiscovery)
  // =========================================================================
  console.log('\n--- Test Suite 7: Unified Discovery Coordinator ---');

  clearCtCache();
  const discResult = await runPassiveDiscovery({
    organizationId: orgId,
    rootDomain: 'acme.com',
    parentVerified: true,
    skipCtLog: true, // skip network call for deterministic unit test
    permutationWordlist: ['app', 'portal'],
  });

  assert(discResult.rootDomain === 'acme.com', 'Returns normalized root domain');
  assert(discResult.sources.ctLog === 0, 'Reports 0 CT sources when skipped');
  assert(Array.isArray(discResult.assets), 'Returns list of processed assets');

  // =========================================================================
  // Test Suite 8: API Endpoints (POST /discover & POST /verify Hook)
  // =========================================================================
  console.log('\n--- Test Suite 8: API Endpoints & Verification Hooks ---');

  // Setup Organization and User
  const testUserId = 'user-disc-admin';
  const testOrgId = 'org-disc-endpoint-test';

  memoryStore.organizations.set(testOrgId, {
    _id: testOrgId,
    name: 'Discovery Test Org',
    plan: 'ENTERPRISE',
    scanQuotas: { maxMonitoredDomains: 10, maxScansPerMonth: 100, scanConcurrency: 5 },
    members: [{ userId: testUserId, role: 'ADMIN', joinedAt: new Date() }],
  });

  memoryStore.users.set(testUserId, {
    _id: testUserId,
    email: 'admin@discoverytest.com',
    name: 'Discovery Admin',
    organizationId: testOrgId,
    role: 'ADMIN',
  });

  const authToken = createSessionToken({
    userId: testUserId,
    email: 'admin@discoverytest.com',
    role: 'ADMIN',
    organizationId: testOrgId,
  });

  // Create an asset for this organization via POST /api/assets
  const createAssetReq = createMockRequest('http://localhost:3000/api/assets', {
    method: 'POST',
    token: authToken,
    body: { domain: 'pliora-test.com', importance: 'HIGH' },
  });

  const createAssetRes = await postAssetRoute(createAssetReq);
  const createAssetJson = await createAssetRes.json();

  assert(createAssetRes.status === 201, 'POST /api/assets creates new root domain asset');
  assert(
    createAssetJson.data.discoveredVia.includes('MANUAL'),
    'Manually created asset has discoveredVia: [MANUAL]'
  );

  const createdAssetId = createAssetJson.data._id;

  // On-demand discovery endpoint POST /api/assets/[id]/discover
  const discoverReq = createMockRequest(`http://localhost:3000/api/assets/${createdAssetId}/discover`, {
    method: 'POST',
    token: authToken,
  });

  const discoverRes = await discoverAssetRoute(discoverReq, { params: { id: createdAssetId } });
  const discoverJson = await discoverRes.json();

  assert(discoverRes.status === 200, 'POST /api/assets/[id]/discover returns HTTP 200');
  assert(discoverJson.success === true, 'POST /api/assets/[id]/discover returns success: true');
  assert(
    discoverJson.data.rootDomain === 'pliora-test.com',
    'Discovery response contains rootDomain'
  );
  assert(
    typeof discoverJson.data.totalDiscovered === 'number',
    'Discovery response returns totalDiscovered count'
  );

  // Check audit log for on-demand discovery
  const discRunAudit = memoryStore.auditLogs.find(
    (l) => l.action === 'ASSET_DISCOVERY_RUN' && l.objectId === createdAssetId
  );
  assert(Boolean(discRunAudit), 'ASSET_DISCOVERY_RUN audit log recorded for on-demand discovery');

  // Test GET /api/assets filter by discoveredVia
  const getAssetsReq = createMockRequest('http://localhost:3000/api/assets?discoveredVia=MANUAL', {
    method: 'GET',
    token: authToken,
  });

  const getAssetsRes = await getAssetsRoute(getAssetsReq);
  const getAssetsJson = await getAssetsRes.json();

  assert(getAssetsRes.status === 200, 'GET /api/assets?discoveredVia=MANUAL returns HTTP 200');
  assert(
    getAssetsJson.data.some((a: any) => a.fqdn === 'pliora-test.com'),
    'GET /api/assets filters by discoveredVia query parameter'
  );

  // =========================================================================
  // Final Test Summary
  // =========================================================================
  console.log('\n=============================================');
  console.log(` Option 4 Test Summary: ${passed} Passed, ${failed} Failed`);
  console.log('=============================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runDiscoveryEngineTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
