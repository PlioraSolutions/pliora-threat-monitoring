import test from 'node:test';
import assert from 'node:assert/strict';
import { pluginRegistry } from '../src/lib/plugins/registry';
import { generateBucketCandidates, clearBucketCandidateCache, MAX_CANDIDATES_PER_DOMAIN } from '../src/lib/plugins/cloudBuckets/candidates';
import { cloudBucketCheckPlugin } from '../src/lib/plugins/cloudBucketCheck';
import { webHygieneCheckPlugin } from '../src/lib/plugins/webHygieneCheck';
import { cmsCheckPlugin } from '../src/lib/plugins/cmsCheck';
import { REMEDIATION_LIBRARY, validateRemediationSteps } from '../src/lib/ai/remediationLibrary';
import { aggregateRiskScore } from '../src/lib/risk/orgScore';
import { PluginContext } from '../src/lib/plugins/types';

test('Wave 2: Cloud Buckets, Web Hygiene, CMS & Trust Signals Plugin Suite', async (t) => {

  // 1. Registry Test
  await t.test('Registry includes all Wave 2 plugins (at least 12 plugins total)', () => {
    const plugins = pluginRegistry.getAllPlugins();
    assert.ok(plugins.length >= 12, 'Registry should have at least 12 plugins loaded');
    assert.ok(pluginRegistry.getPlugin('cloud-bucket-check'), 'cloud-bucket-check should be registered');
    assert.ok(pluginRegistry.getPlugin('web-hygiene-check'), 'web-hygiene-check should be registered');
    assert.ok(pluginRegistry.getPlugin('cms-check'), 'cms-check should be registered');
  });

  // 2. Cloud Storage Bucket Candidate Generator
  await t.test('Cloud Storage Bucket: Candidate Generation & Bounding Discipline', () => {
    clearBucketCandidateCache();
    const candidates = generateBucketCandidates('example.com', 'Acme Corporation');

    assert.ok(candidates.length > 0, 'Should generate candidates');
    assert.ok(candidates.length <= MAX_CANDIDATES_PER_DOMAIN, 'Must respect MAX_CANDIDATES_PER_DOMAIN ceiling');
    assert.ok(candidates.includes('example'), 'Must include root domain base');
    assert.ok(candidates.includes('example-backup'), 'Must include suffix variant');
    assert.ok(candidates.includes('acme') || candidates.includes('acmecorporation'), 'Must include org base');

    // Verify caching behavior
    const cached = generateBucketCandidates('example.com', 'Acme Corporation');
    assert.deepEqual(cached, candidates, 'Cache should return identical candidate array');
  });

  // 3. Cloud Storage Bucket Probes & Confidence Discipline
  await t.test('Cloud Storage Bucket: Public-Read vs Private vs Nonexistent Probes', async () => {
    // 3.1 Public S3 Bucket with Real XML Listing
    const mockCtxPublicS3: PluginContext = {
      safeFetch: async (url: string) => {
        if (url.includes('example-backup.s3.amazonaws.com')) {
          const publicXml = `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>example-backup</Name>
    <Prefix></Prefix>
    <Marker></Marker>
    <MaxKeys>1000</MaxKeys>
    <IsTruncated>false</IsTruncated>
    <Contents>
        <Key>database-dump-2026.sql.gz</Key>
        <LastModified>2026-01-01T00:00:00.000Z</LastModified>
        <ETag>"b10a8db164e0754105b7a99be72e3fe5"</ETag>
        <Size>10485760</Size>
        <StorageClass>STANDARD</StorageClass>
    </Contents>
</ListBucketResult>`;
          return new Response(publicXml, {
            status: 200,
            headers: { 'Content-Type': 'application/xml' },
          });
        }
        throw new Error('ENOTFOUND');
      },
      safeTlsHandshake: async () => ({} as any),
      scanId: 'test-scan',
      organizationId: 'test-org',
      timeoutMs: 4000,
    };

    const resultPublic = await cloudBucketCheckPlugin.run(
      { fqdn: 'example.com', type: 'ROOT_DOMAIN' },
      mockCtxPublicS3
    );

    assert.equal(resultPublic.status, 'COMPLETED');
    const publicFinding = resultPublic.findings.find(f => f.findingCode === 'CLOUD-BUCKET-PUBLIC-LISTING-S3');
    assert.ok(publicFinding, 'Must identify public S3 listing finding');
    assert.equal(publicFinding.severity, 'HIGH');
    assert.equal(publicFinding.confidence, 'CONFIRMED', 'Real listing must be CONFIRMED');
    assert.ok(publicFinding.description.includes('database-dump-2026.sql.gz'));

    // 3.2 Private Bucket (AccessDenied)
    const mockCtxPrivate: PluginContext = {
      safeFetch: async (url: string) => {
        if (url.includes('example-backup.s3.amazonaws.com')) {
          const deniedXml = `<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>AccessDenied</Code>
    <Message>Access Denied</Message>
    <RequestId>ABCD1234EFGH</RequestId>
</Error>`;
          return new Response(deniedXml, {
            status: 403,
            headers: { 'Content-Type': 'application/xml' },
          });
        }
        throw new Error('ENOTFOUND');
      },
      safeTlsHandshake: async () => ({} as any),
      scanId: 'test-scan',
      organizationId: 'test-org',
      timeoutMs: 4000,
    };

    const resultPrivate = await cloudBucketCheckPlugin.run(
      { fqdn: 'example.com', type: 'ROOT_DOMAIN' },
      mockCtxPrivate
    );

    assert.equal(resultPrivate.status, 'COMPLETED');
    const privateFinding = resultPrivate.findings.find(f => f.findingCode === 'CLOUD-BUCKET-EXISTS-PRIVATE');
    assert.ok(privateFinding, 'Must record private bucket as informational finding');
    assert.equal(privateFinding.severity, 'INFORMATIONAL', 'Private bucket is not a vulnerability');

    // 3.3 Anti-SPA Filtering: HTML 200 OK must not trigger finding
    const mockCtxSpaHtml: PluginContext = {
      safeFetch: async () => {
        return new Response('<!DOCTYPE html><html><body>SPA Application Root</body></html>', {
          status: 200,
          headers: { 'Content-Type': 'text/html' },
        });
      },
      safeTlsHandshake: async () => ({} as any),
      scanId: 'test-scan',
      organizationId: 'test-org',
      timeoutMs: 4000,
    };

    const resultSpa = await cloudBucketCheckPlugin.run(
      { fqdn: 'example.com', type: 'ROOT_DOMAIN' },
      mockCtxSpaHtml
    );
    assert.equal(resultSpa.findings.length, 0, 'SPA HTML 200 response must be discarded by anti-false-positive filter');
  });

  // 4. Web Application Hygiene Plugin
  await t.test('Web Hygiene: CORS, Mixed Content, SRI, Cookies & JS Vulnerabilities', async () => {
    const mockCtxHygiene: PluginContext = {
      safeFetch: async (url: string, options?: any) => {
        // Handle OPTIONS request for CORS check
        if (options?.method === 'OPTIONS') {
          return new Response(null, {
            status: 204,
            headers: {
              'Access-Control-Allow-Origin': 'https://evil-attacker.com',
              'Access-Control-Allow-Credentials': 'true',
              'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            },
          });
        }

        // Return HTML response containing mixed content, missing SRI, outdated jQuery, and insecure cookie
        const sampleHtml = `<!DOCTYPE html>
<html>
<head>
  <title>Corporate Portal</title>
  <!-- Missing SRI on 3rd party script -->
  <script src="https://cdn.thirdparty.com/analytics.js"></script>
  <!-- Vulnerable jQuery v3.4.1 -->
  <script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>
  <!-- CMP Signature -->
  <script src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js"></script>
  <!-- Passive mixed content -->
  <link rel="stylesheet" href="http://cdn.example.com/styles.css">
</head>
<body>
  <!-- Active mixed content -->
  <script src="http://legacy-sub.example.com/widget.js"></script>
</body>
</html>`;

        return new Response(sampleHtml, {
          status: 200,
          headers: {
            'Content-Type': 'text/html',
            'Set-Cookie': 'session_id=auth_token_xyz123; Path=/',
          },
        });
      },
      safeTlsHandshake: async () => ({} as any),
      scanId: 'test-scan',
      organizationId: 'test-org',
      timeoutMs: 4000,
    };

    const result = await webHygieneCheckPlugin.run(
      { fqdn: 'app.example.com', type: 'SUBDOMAIN' },
      mockCtxHygiene
    );

    assert.equal(result.status, 'COMPLETED');

    // 1. CORS check
    const corsFinding = result.findings.find(f => f.findingCode === 'CORS-MISCONFIG-CREDENTIALS-REFLECTED');
    assert.ok(corsFinding, 'Must detect CORS origin reflection with credentials');
    assert.equal(corsFinding.severity, 'HIGH');
    assert.equal(corsFinding.confidence, 'CONFIRMED');

    // 2. Active Mixed Content
    const activeMixed = result.findings.find(f => f.findingCode === 'MIXED-CONTENT-ACTIVE-SCRIPT');
    assert.ok(activeMixed, 'Must detect active mixed content script');
    assert.equal(activeMixed.severity, 'HIGH');

    // 3. Passive Mixed Content
    const passiveMixed = result.findings.find(f => f.findingCode === 'MIXED-CONTENT-PASSIVE-RESOURCE');
    assert.ok(passiveMixed, 'Must detect passive mixed content stylesheet');
    assert.equal(passiveMixed.severity, 'LOW');

    // 4. Missing SRI
    const sriFinding = result.findings.find(f => f.findingCode === 'SRI-MISSING-EXTERNAL-RESOURCE');
    assert.ok(sriFinding, 'Must detect missing SRI on third-party script');
    assert.equal(sriFinding.severity, 'LOW');

    // 5. Insecure Session Cookie
    const cookieFinding = result.findings.find(f => f.findingCode === 'COOKIE-FLAG-SESSION-INSECURE');
    assert.ok(cookieFinding, 'Must flag session_id cookie missing HttpOnly/Secure');
    assert.equal(cookieFinding.severity, 'MEDIUM');

    // 6. Client-Side JS Library Vulnerability & Hard Confidence Guard
    const jsFinding = result.findings.find(f => f.findingCode === 'JS-LIB-VULN-OUTDATED');
    assert.ok(jsFinding, 'Must identify outdated jQuery 3.4.1');
    assert.equal(jsFinding.severity, 'MEDIUM');
    assert.equal(jsFinding.confidence, 'MEDIUM', 'STRICT DISCIPLINE: Version matching must be capped at MEDIUM confidence');

    // 7. Cookie Consent CMP Detection
    const cmpFinding = result.findings.find(f => f.findingCode === 'TRUST-COOKIE-CONSENT-DETECTED');
    assert.ok(cmpFinding, 'Must detect OneTrust CMP signature');
    assert.equal(cmpFinding.severity, 'INFORMATIONAL');
  });

  // 5. WordPress & CMS-Specific Checks
  await t.test('WordPress & CMS Checks: Version, Outdated Plugins, Login & XML-RPC', async () => {
    const mockCtxCms: PluginContext = {
      safeFetch: async (url: string) => {
        if (url.endsWith('/wp-login.php')) {
          return new Response(
            '<form name="loginform" id="loginform"><input type="text" name="user_login" /><input type="submit" name="wp-submit" /></form>',
            { status: 200 }
          );
        }
        if (url.endsWith('/xmlrpc.php')) {
          return new Response('XML-RPC server accepts POST requests only.', { status: 200 });
        }
        if (url.endsWith('/readme.html')) {
          return new Response('<h1 id="logo">WordPress</h1><p>Version 5.8.1</p>', { status: 200 });
        }
        // Home page HTML with outdated WP plugin link
        return new Response(
          '<html><head><meta name="generator" content="WordPress 5.8.1" /><script src="/wp-content/plugins/wp-file-manager/js/ui.js?ver=6.5"></script></head><body>WordPress Blog</body></html>',
          { status: 200 }
        );
      },
      safeTlsHandshake: async () => ({} as any),
      scanId: 'test-scan',
      organizationId: 'test-org',
      timeoutMs: 4000,
    };

    const result = await cmsCheckPlugin.run(
      { fqdn: 'blog.example.com', type: 'SUBDOMAIN' },
      mockCtxCms
    );

    assert.equal(result.status, 'COMPLETED');

    // 1. WordPress Outdated Core
    const coreFinding = result.findings.find(f => f.findingCode === 'WP-CORE-OUTDATED');
    assert.ok(coreFinding, 'Must identify outdated WordPress 5.8.1');
    assert.equal(coreFinding.confidence, 'MEDIUM', 'Version fingerprinting must be capped at MEDIUM confidence');

    // 2. Outdated Plugin
    const pluginFinding = result.findings.find(f => f.findingCode === 'WP-OUTDATED-PLUGIN-DETECTED');
    assert.ok(pluginFinding, 'Must detect vulnerable WP File Manager v6.5');
    assert.equal(pluginFinding.confidence, 'MEDIUM', 'Plugin version string match must be capped at MEDIUM confidence');
    assert.ok(pluginFinding.description.includes('CVE-2020-25213'));

    // 3. Login reachability (Contextual Informational)
    const loginFinding = result.findings.find(f => f.findingCode === 'WP-LOGIN-EXPOSED');
    assert.ok(loginFinding, 'Must detect reachable wp-login.php');
    assert.equal(loginFinding.severity, 'INFORMATIONAL', 'Login reachability must be framed contextually, not alarmist');

    // 4. XML-RPC exposed
    const xmlrpcFinding = result.findings.find(f => f.findingCode === 'WP-XMLRPC-EXPOSED');
    assert.ok(xmlrpcFinding, 'Must detect exposed XML-RPC endpoint');
    assert.equal(xmlrpcFinding.severity, 'LOW');
  });

  // 6. Compliance & Trust Indicators: Posture Score Contribution
  await t.test('Trust Indicators: security.txt Presence Contributes +5 Posture Resilience Bonus', () => {
    // Standard organization findings with some risk
    const baseFindings = [
      { severity: 'HIGH' as const, status: 'OPEN' as const, riskScore: 50 },
      { severity: 'MEDIUM' as const, status: 'OPEN' as const, riskScore: 30 },
    ];

    const scoreWithoutSecurityTxt = aggregateRiskScore(baseFindings);

    const findingsWithSecurityTxt = [
      ...baseFindings,
      {
        severity: 'INFORMATIONAL' as const,
        status: 'OPEN' as const,
        riskScore: 0,
        findingCode: 'TRUST-SECURITY-TXT-PRESENT',
      },
    ];

    const scoreWithSecurityTxt = aggregateRiskScore(findingsWithSecurityTxt);

    assert.ok(
      scoreWithSecurityTxt.securityPosture >= scoreWithoutSecurityTxt.securityPosture,
      'Presence of security.txt must positively reinforce security posture'
    );
    assert.equal(
      scoreWithSecurityTxt.securityPosture,
      Math.min(100, scoreWithoutSecurityTxt.securityPosture + 5),
      'Must award +5 point posture bonus'
    );
  });

  // 7. Remediation Library & AI Grounding Coverage
  await t.test('Remediation Library: All Wave 2 Finding Codes Are Fully Covered & Validated', () => {
    const wave2Codes = [
      'CLOUD-BUCKET-PUBLIC-LISTING-S3',
      'CLOUD-BUCKET-PUBLIC-LISTING-GCS',
      'CLOUD-BUCKET-PUBLIC-LISTING-AZURE',
      'CLOUD-BUCKET-EXISTS-PRIVATE',
      'CORS-MISCONFIG-CREDENTIALS-REFLECTED',
      'CORS-WILDCARD-ORIGIN',
      'MIXED-CONTENT-ACTIVE-SCRIPT',
      'MIXED-CONTENT-PASSIVE-RESOURCE',
      'SRI-MISSING-EXTERNAL-RESOURCE',
      'COOKIE-FLAG-SESSION-INSECURE',
      'COOKIE-FLAG-GENERAL-INSECURE',
      'JS-LIB-VULN-OUTDATED',
      'WP-CORE-OUTDATED',
      'WP-OUTDATED-PLUGIN-DETECTED',
      'WP-LOGIN-EXPOSED',
      'WP-XMLRPC-EXPOSED',
      'TRUST-SECURITY-TXT-PRESENT',
      'TRUST-COOKIE-CONSENT-DETECTED',
    ];

    for (const code of wave2Codes) {
      const entry = REMEDIATION_LIBRARY[code];
      assert.ok(entry, `Remediation library must contain guidance for code "${code}"`);
      assert.ok(entry.approvedSteps.length >= 2, `Guidance for "${code}" must contain multiple actionable steps`);
      assert.equal(entry.version, '1.1.0', `Guidance for "${code}" should be version 1.1.0`);

      // Test validation logic
      const valResult = validateRemediationSteps(code, [entry.approvedSteps[0]]);
      assert.equal(valResult.valid, true, `Approved step for "${code}" must validate cleanly`);
    }

    // Verify PCI DSS 4.0 framing on TLS guidance
    const tlsEntry = REMEDIATION_LIBRARY['TLS-OBSOLETE-PROTOCOL'];
    assert.ok(tlsEntry, 'TLS-OBSOLETE-PROTOCOL must exist');
    assert.ok(
      tlsEntry.approvedSteps.some(s => s.includes('PCI DSS 4.0')),
      'TLS guidance must include PCI DSS 4.0 compliance framing'
    );
  });
});
