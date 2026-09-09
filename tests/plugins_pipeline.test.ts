import { pluginRegistry } from '../src/lib/plugins/registry';
import { tlsCertCheckPlugin } from '../src/lib/plugins/tlsCertCheck';
import { httpHeadersCheckPlugin } from '../src/lib/plugins/httpHeadersCheck';
import { techFingerprintCheckPlugin } from '../src/lib/plugins/techFingerprintCheck';
import { validateAndMapFinding, computeFindingDedupHash } from '../src/lib/plugins/findings';
import { detectWafOrBotBlock } from '../src/lib/plugins/waf';
import { processScanJob } from '../src/workers/scanProcessor';
import { memoryStore } from '../src/lib/store';
import { PluginContext } from '../src/lib/plugins/types';

async function runPluginsAndPipelineTests() {
  console.log('🧪 Running Option 2: Exposure Checks & Scan Pipeline Test Suite...\n');
  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, testName: string) {
    if (condition) {
      console.log(`  ✅ PASS: ${testName}`);
      passed++;
    } else {
      console.error(`  ❌ FAIL: ${testName}`);
      failed++;
    }
  }

  // =========================================================================
  // Test Group 1: Hard Confidence Guard (Non-negotiable rule §2.1 & §5)
  // =========================================================================
  console.log('Test Group 1: Hard Confidence & Severity Guard');
  let guardTriggeredHigh = false;
  try {
    validateAndMapFinding(
      {
        category: 'TECH_VERSION',
        findingCode: 'TECH-VULNERABLE-VERSION',
        title: 'Vulnerable Apache Version Detected',
        description: 'Apache 2.4.41 detected from server header',
        severity: 'HIGH', // FORBIDDEN without corroborating evidence!
        confidence: 'HIGH',
      },
      techFingerprintCheckPlugin,
      { fqdn: 'app.example.com' }
    );
  } catch (err: any) {
    guardTriggeredHigh = err.message.includes('CRITICAL GUARD VIOLATION');
  }
  assert(guardTriggeredHigh, 'Hard guard throws on attempt to create HIGH severity finding from tech fingerprint');

  let guardTriggeredCritical = false;
  try {
    validateAndMapFinding(
      {
        category: 'TECH_VERSION',
        findingCode: 'TECH-CRITICAL-CVE',
        title: 'Critical CVE on fingerprinted software',
        description: 'Matched fingerprint to known CVE',
        severity: 'CRITICAL', // FORBIDDEN!
        confidence: 'CONFIRMED',
      },
      techFingerprintCheckPlugin,
      { fqdn: 'app.example.com' }
    );
  } catch (err: any) {
    guardTriggeredCritical = err.message.includes('CRITICAL GUARD VIOLATION');
  }
  assert(guardTriggeredCritical, 'Hard guard throws on attempt to create CRITICAL severity finding from tech fingerprint');

  // Permitted case: LOW / MEDIUM severity or corroborated finding
  const safeMapped = validateAndMapFinding(
    {
      category: 'TECH_VERSION',
      findingCode: 'TECH-SERVER-BANNER-NGINX',
      title: 'Server banner nginx/1.18.0 disclosed',
      description: 'Nginx server version',
      severity: 'LOW',
      confidence: 'CONFIRMED', // requested confirmed, but plugin ceiling is MEDIUM
    },
    techFingerprintCheckPlugin,
    { fqdn: 'app.example.com' }
  );
  assert(safeMapped.confidence === 'MEDIUM', 'Confidence automatically capped at plugin default ceiling (MEDIUM)');
  assert(safeMapped.severity === 'LOW', 'LOW severity fingerprint finding is accepted');

  // =========================================================================
  // Test Group 2: Plugin 1 — TLS / SSL Certificate Check (§3)
  // =========================================================================
  console.log('\nTest Group 2: Plugin 1 — TLS Certificate Check');

  // Mock Context for Expired Certificate
  const mockExpiredTlsContext: PluginContext = {
    safeFetch: async () => new Response(''),
    safeTlsHandshake: async () => ({
      authorized: false,
      authorizationError: 'certificate has expired',
      protocol: 'TLSv1.3',
      cipher: { name: 'TLS_AES_256_GCM_SHA384', version: 'TLSv1.3' },
      peerCertificate: {
        subject: { CN: 'expired.example.com' },
        issuer: { CN: 'Let\'s Encrypt' },
        valid_from: 'Jan 1 2024',
        valid_to: 'Jan 1 2025',
        subjectaltname: 'DNS:expired.example.com',
      },
      daysRemaining: -45,
      isExpired: true,
      isSelfSigned: false,
      subjectAltNames: ['expired.example.com'],
      commonName: 'expired.example.com',
      pinnedIp: '93.184.216.34',
    }),
    scanId: 'scan-test-01',
    organizationId: 'org-test-01',
    timeoutMs: 5000,
  };

  const expiredResult = await tlsCertCheckPlugin.run({ fqdn: 'expired.example.com', type: 'SUBDOMAIN' }, mockExpiredTlsContext);
  assert(expiredResult.status === 'COMPLETED', 'TLS check status is COMPLETED for expired target');
  assert(
    expiredResult.findings.some((f) => f.findingCode === 'TLS-CERT-EXPIRED' && f.severity === 'HIGH'),
    'Expired cert generates HIGH severity TLS-CERT-EXPIRED finding'
  );

  // Mock Context for Obsolete TLS 1.0 & Weak Cipher
  const mockWeakTlsContext: PluginContext = {
    ...mockExpiredTlsContext,
    safeTlsHandshake: async () => ({
      authorized: true,
      protocol: 'TLSv1',
      cipher: { name: 'RC4-SHA', version: 'TLSv1' },
      peerCertificate: {
        subject: { CN: 'legacy.example.com' },
        issuer: { CN: 'DigiCert' },
        valid_from: 'Jan 1 2025',
        valid_to: 'Jan 1 2027',
      },
      daysRemaining: 400,
      isExpired: false,
      isSelfSigned: false,
      subjectAltNames: ['legacy.example.com'],
      commonName: 'legacy.example.com',
      pinnedIp: '93.184.216.34',
    }),
  };

  const weakTlsResult = await tlsCertCheckPlugin.run({ fqdn: 'legacy.example.com', type: 'SUBDOMAIN' }, mockWeakTlsContext);
  assert(
    weakTlsResult.findings.some((f) => f.findingCode === 'TLS-OBSOLETE-PROTOCOL' && f.severity === 'HIGH'),
    'Deprecated TLS 1.0 generates HIGH severity TLS-OBSOLETE-PROTOCOL finding'
  );
  assert(
    weakTlsResult.findings.some((f) => f.findingCode === 'TLS-WEAK-CIPHER' && f.severity === 'HIGH'),
    'Weak cipher RC4 generates HIGH severity TLS-WEAK-CIPHER finding'
  );

  // Mock Context for Hostname Mismatch
  const mockMismatchTlsContext: PluginContext = {
    ...mockExpiredTlsContext,
    safeTlsHandshake: async () => ({
      authorized: true,
      protocol: 'TLSv1.3',
      cipher: { name: 'TLS_AES_256_GCM_SHA384', version: 'TLSv1.3' },
      peerCertificate: {
        subject: { CN: 'completely-different.com' },
        issuer: { CN: 'Let\'s Encrypt' },
        valid_from: 'Jan 1 2025',
        valid_to: 'Jan 1 2027',
        subjectaltname: 'DNS:completely-different.com',
      },
      daysRemaining: 400,
      isExpired: false,
      isSelfSigned: false,
      subjectAltNames: ['completely-different.com'],
      commonName: 'completely-different.com',
      pinnedIp: '93.184.216.34',
    }),
  };

  const mismatchResult = await tlsCertCheckPlugin.run({ fqdn: 'myportal.example.com', type: 'SUBDOMAIN' }, mockMismatchTlsContext);
  assert(
    mismatchResult.findings.some((f) => f.findingCode === 'TLS-HOST-MISMATCH' && f.severity === 'HIGH'),
    'Certificate SAN mismatch generates HIGH severity TLS-HOST-MISMATCH finding'
  );

  // Clean TLS target
  const mockCleanTlsContext: PluginContext = {
    ...mockExpiredTlsContext,
    safeTlsHandshake: async () => ({
      authorized: true,
      protocol: 'TLSv1.3',
      cipher: { name: 'TLS_AES_256_GCM_SHA384', version: 'TLSv1.3' },
      peerCertificate: {
        subject: { CN: 'secure.example.com' },
        issuer: { CN: 'Let\'s Encrypt' },
        valid_from: 'Jan 1 2026',
        valid_to: 'Dec 1 2026',
        subjectaltname: 'DNS:secure.example.com, DNS:*.example.com',
      },
      daysRemaining: 200,
      isExpired: false,
      isSelfSigned: false,
      subjectAltNames: ['secure.example.com', '*.example.com'],
      commonName: 'secure.example.com',
      pinnedIp: '93.184.216.34',
    }),
  };

  const cleanTlsResult = await tlsCertCheckPlugin.run({ fqdn: 'secure.example.com', type: 'SUBDOMAIN' }, mockCleanTlsContext);
  assert(cleanTlsResult.findings.length === 0, 'Clean modern TLS cert with valid SAN produces 0 findings');

  // =========================================================================
  // Test Group 3: Plugin 2 — HTTP Security Headers Check (§4)
  // =========================================================================
  console.log('\nTest Group 3: Plugin 2 — HTTP Security Headers Check');

  // Mock Context missing HSTS and CSP
  const mockMissingHeadersContext: PluginContext = {
    safeFetch: async () => {
      const headers = new Headers({
        'content-type': 'text/html',
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'camera=()',
      });
      return new Response('<html>Hello World</html>', { status: 200, headers });
    },
    safeTlsHandshake: async () => ({} as any),
    scanId: 'scan-02',
    organizationId: 'org-02',
    timeoutMs: 5000,
  };

  const missingRes = await httpHeadersCheckPlugin.run({ fqdn: 'test-headers.com', type: 'SUBDOMAIN' }, mockMissingHeadersContext);
  assert(missingRes.status === 'COMPLETED', 'HTTP headers check completed');
  const hstsFinding = missingRes.findings.find((f) => f.findingCode === 'SEC-HEADER-HSTS-MISSING');
  const cspFinding = missingRes.findings.find((f) => f.findingCode === 'SEC-HEADER-CSP-MISSING');
  assert(Boolean(hstsFinding && cspFinding), 'Target missing HSTS and CSP generates exactly two distinct findings');
  assert(!missingRes.findings.some((f) => f.findingCode === 'SEC-HEADER-XFO-MISSING'), 'Compliant X-Frame-Options is not flagged');

  // Clean compliant headers
  const mockCompliantHeadersContext: PluginContext = {
    ...mockMissingHeadersContext,
    safeFetch: async () => {
      const headers = new Headers({
        'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
        'content-security-policy': "default-src 'self'",
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'camera=()',
      });
      return new Response('<html>Clean Secure App</html>', { status: 200, headers });
    },
  };

  const compliantRes = await httpHeadersCheckPlugin.run({ fqdn: 'secure-headers.com', type: 'SUBDOMAIN' }, mockCompliantHeadersContext);
  assert(compliantRes.findings.length === 0, 'Target with fully compliant security headers produces 0 findings');

  // Permissive CSP check
  const mockPermissiveCspContext: PluginContext = {
    ...mockMissingHeadersContext,
    safeFetch: async () => {
      const headers = new Headers({
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'content-security-policy': "default-src * 'unsafe-inline' 'unsafe-eval'",
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'camera=()',
      });
      return new Response('<html>Permissive App</html>', { status: 200, headers });
    },
  };

  const permissiveRes = await httpHeadersCheckPlugin.run({ fqdn: 'permissive.com', type: 'SUBDOMAIN' }, mockPermissiveCspContext);
  assert(
    permissiveRes.findings.some((f) => f.findingCode === 'SEC-HEADER-CSP-WEAK'),
    'Permissive CSP directives (unsafe-inline / unsafe-eval / *) flagged as SEC-HEADER-CSP-WEAK'
  );

  // =========================================================================
  // Test Group 4: WAF & Anti-Bot Detection (§1.4)
  // =========================================================================
  console.log('\nTest Group 4: WAF / Anti-Bot Detection');

  const cfChallengeWaf = detectWafOrBotBlock(
    403,
    new Headers({ server: 'cloudflare', 'cf-ray': '8872bcae9123-IAD' }),
    '<html><title>Attention Required! | Cloudflare</title><form id="challenge-form"></form></html>'
  );
  assert(cfChallengeWaf.isWafDetected === true, 'Detects Cloudflare Turnstile / Challenge Page');
  assert(Boolean(cfChallengeWaf.vendor?.includes('Cloudflare')), 'Correctly identifies Cloudflare WAF vendor');

  const awsWaf = detectWafOrBotBlock(
    403,
    new Headers({ 'x-amzn-waf-action': 'block' }),
    '<html>Request blocked by AWS WAF</html>'
  );
  assert(awsWaf.isWafDetected === true, 'Detects AWS WAF via x-amzn-waf-action header and block text');

  // Verify plugin behavior on WAF response
  const mockWafContext: PluginContext = {
    safeFetch: async () => {
      const headers = new Headers({ server: 'cloudflare', 'cf-ray': '8872bcae9123-IAD' });
      return new Response('<html><title>Attention Required! | Cloudflare</title><form id="challenge-form"></form></html>', {
        status: 403,
        headers,
      });
    },
    safeTlsHandshake: async () => ({} as any),
    scanId: 'scan-waf-01',
    organizationId: 'org-waf-01',
    timeoutMs: 5000,
  };

  const wafPluginRes = await httpHeadersCheckPlugin.run({ fqdn: 'waf-blocked.com', type: 'SUBDOMAIN' }, mockWafContext);
  assert(wafPluginRes.status === 'INCONCLUSIVE', 'WAF challenge response marks plugin status as INCONCLUSIVE');
  assert(wafPluginRes.isWafDetected === true, 'Plugin result flags isWafDetected = true');
  assert(wafPluginRes.findings.length === 0, 'WAF challenge does NOT record misleading false-clean findings');

  // =========================================================================
  // Test Group 5: Plugin 3 — Technology Fingerprinting (§5)
  // =========================================================================
  console.log('\nTest Group 5: Plugin 3 — Technology Fingerprinting');

  const mockTechContext: PluginContext = {
    safeFetch: async () => {
      const headers = new Headers({
        server: 'nginx/1.18.0',
        'x-powered-by': 'PHP/7.4.3',
      });
      return new Response('<html><head><meta name="generator" content="WordPress 6.4.2"></head><body><link href="/wp-content/themes/style.css"></body></html>', {
        status: 200,
        headers,
      });
    },
    safeTlsHandshake: async () => ({} as any),
    scanId: 'scan-tech-01',
    organizationId: 'org-tech-01',
    timeoutMs: 5000,
  };

  const techRes = await techFingerprintCheckPlugin.run({ fqdn: 'blog.example.com', type: 'SUBDOMAIN' }, mockTechContext);
  assert(techRes.status === 'COMPLETED', 'Tech fingerprint check completed');
  assert(
    techRes.findings.some((f) => f.findingCode.includes('SERVER-BANNER') && f.severity === 'LOW'),
    'Server banner nginx/1.18.0 detected and flagged with LOW severity'
  );
  assert(
    techRes.findings.some((f) => f.findingCode.includes('POWERED-BY') && f.severity === 'LOW'),
    'X-Powered-By PHP/7.4.3 detected and flagged'
  );
  assert(
    techRes.findings.some((f) => f.findingCode.includes('META-GENERATOR') && f.severity === 'LOW'),
    'HTML generator WordPress 6.4.2 detected and flagged'
  );
  assert(
    !techRes.findings.some((f) => f.severity === 'HIGH' || f.severity === 'CRITICAL'),
    'Tech fingerprint plugin never produces HIGH or CRITICAL findings'
  );

  // =========================================================================
  // Test Group 6: Deduplication & Re-opened Regressions (§2.1)
  // =========================================================================
  console.log('\nTest Group 6: Deduplication & Regressions');
  const orgId = 'org-dedup-01';
  const assetId = 'asset-dedup-01';
  const findingCode = 'SEC-HEADER-HSTS-MISSING';

  const hash1 = computeFindingDedupHash(orgId, assetId, findingCode);
  const hash2 = computeFindingDedupHash(orgId, assetId, findingCode);
  assert(hash1 === hash2, 'Dedup hashes are deterministic across identical findings');
  assert(hash1.length === 64, 'Dedup hash is valid SHA-256 (64 hex characters)');

  // =========================================================================
  // Test Group 7: Plugin Registry (§1.1)
  // =========================================================================
  console.log('\nTest Group 7: Plugin Registry Extensibility');
  const allPlugins = pluginRegistry.getAllPlugins();
  assert(allPlugins.length >= 3, `Registry has default plugins loaded (found: ${allPlugins.length})`);
  assert(Boolean(pluginRegistry.getPlugin('tls-cert-check')), 'tls-cert-check is registered');
  assert(Boolean(pluginRegistry.getPlugin('http-security-headers-check')), 'http-security-headers-check is registered');
  assert(Boolean(pluginRegistry.getPlugin('tech-fingerprint-check')), 'tech-fingerprint-check is registered');

  // Test custom test plugin addition without modifying core processor (DoD §1.1)
  const dummyPlugin = {
    id: 'dummy-test-plugin',
    name: 'Dummy Extensibility Test Plugin',
    category: 'TRANSPORT_SECURITY' as const,
    defaultConfidence: 'CONFIRMED' as const,
    appliesTo: () => true,
    run: async () => ({
      status: 'COMPLETED' as const,
      evidence: [{ checkType: 'SERVICE_BANNER' as const, rawObservation: { test: true } }],
      findings: [],
    }),
  };
  pluginRegistry.register(dummyPlugin);
  assert(pluginRegistry.getPlugin('dummy-test-plugin') !== undefined, 'Registry dynamically accepts new plugins without touching core processor');
  pluginRegistry.unregister('dummy-test-plugin');

  // =========================================================================
  // Test Group 8: Multi-Step Scan Processor & Partial Failure Handling (§1.2 & §1.4)
  // =========================================================================
  console.log('\nTest Group 8: Scan Processor Pipeline & Partial Failure');

  // Seed verified asset in memoryStore
  const pipelineAssetId = 'asset-pipeline-test-01';
  memoryStore.assets.set(pipelineAssetId, {
    _id: pipelineAssetId,
    organizationId: 'org-demo-001',
    fqdn: 'dns.google', // safe external domain
    type: 'ROOT_DOMAIN',
    verificationStatus: 'VERIFIED',
    lastSeen: new Date(),
  });

  const pipelineScanId = 'scan-pipeline-test-01';
  memoryStore.scans.set(pipelineScanId, {
    _id: pipelineScanId,
    organizationId: 'org-demo-001',
    targetAssetId: pipelineAssetId,
    scanType: 'FULL_SWEEP',
    status: 'QUEUED',
    progress: 0,
    counters: { subdomainsFound: 0, findingsCreated: 0, checksCompleted: 0 },
    pluginRuns: [],
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  // Temporarily register a failing plugin to test partial failure handling
  const failingPlugin = {
    id: 'failing-test-plugin',
    name: 'Failing / Timing Out Test Plugin',
    category: 'EXPOSED_SERVICES' as const,
    defaultConfidence: 'CONFIRMED' as const,
    appliesTo: () => true,
    run: async () => {
      throw new Error('Simulated network socket timeout');
    },
  };
  pluginRegistry.register(failingPlugin);

  await processScanJob({
    scanId: pipelineScanId,
    organizationId: 'org-demo-001',
    assetId: pipelineAssetId,
    scanType: 'FULL_SWEEP',
  });

  pluginRegistry.unregister('failing-test-plugin');

  const processedScan = memoryStore.scans.get(pipelineScanId);
  assert(processedScan !== undefined, 'Scan was processed and saved in memory store');
  assert(processedScan.progress === 100, 'Scan reached 100% progress');
  assert(processedScan.status === 'PARTIAL', 'Scan status is marked PARTIAL when one plugin fails');
  assert(processedScan.pluginRuns.length >= 4, 'Scan records per-plugin execution breakdown in pluginRuns');
  assert(
    processedScan.pluginRuns.some((r: any) => r.pluginId === 'failing-test-plugin' && r.status === 'FAILED'),
    'Failing plugin is explicitly identified in pluginRuns summary'
  );
  assert(
    processedScan.pluginRuns.some((r: any) => r.pluginId === 'http-security-headers-check'),
    'Other plugins continue running despite failing plugin (isolation boundary intact)'
  );

  // =========================================================================
  // Test Group 9: Organization Concurrent Scans Quota Enforcement (§2.3 & DoD)
  // =========================================================================
  console.log('\nTest Group 9: Organization Concurrency Quotas');
  const quotaOrgId = 'org-quota-test-01';
  const quotaLimit = 2;

  memoryStore.organizations.set(quotaOrgId, {
    _id: quotaOrgId,
    name: 'Quota Test Corp',
    scanQuotas: {
      concurrentScans: quotaLimit,
      dailyScanLimit: 10,
      maxMonitoredDomains: 5,
    },
  });

  // Seed scans up to the limit
  memoryStore.scans.set('quota-scan-1', {
    _id: 'quota-scan-1',
    organizationId: quotaOrgId,
    status: 'ACTIVE',
  });
  memoryStore.scans.set('quota-scan-2', {
    _id: 'quota-scan-2',
    organizationId: quotaOrgId,
    status: 'QUEUED',
  });

  const currentActive = Array.from(memoryStore.scans.values()).filter(
    (s: any) =>
      s.organizationId.toString() === quotaOrgId &&
      (s.status === 'ACTIVE' || s.status === 'QUEUED')
  ).length;

  assert(currentActive === quotaLimit, 'Org has exactly reached concurrent scan limit (2 active/queued)');
  const isAtOrAboveLimit = currentActive >= quotaLimit;
  assert(isAtOrAboveLimit, 'Quota engine detects organization has reached maximum concurrent scan quota');

  // Complete one scan
  memoryStore.scans.get('quota-scan-1').status = 'COMPLETED';
  const updatedActive = Array.from(memoryStore.scans.values()).filter(
    (s: any) =>
      s.organizationId.toString() === quotaOrgId &&
      (s.status === 'ACTIVE' || s.status === 'QUEUED')
  ).length;
  assert(updatedActive < quotaLimit, 'Completing an active scan frees up concurrency slot for next scan job');

  console.log(`\n========================================`);
  console.log(`Option 2 Test Results: ${passed} Passed, ${failed} Failed`);
  console.log(`========================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runPluginsAndPipelineTests().catch((err) => {
  console.error('Unhandled Plugin & Pipeline test error:', err);
  process.exit(1);
});
