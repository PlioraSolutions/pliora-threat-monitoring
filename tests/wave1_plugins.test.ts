import test from 'node:test';
import assert from 'node:assert/strict';
import { emailSecurityCheckPlugin } from '../src/lib/plugins/emailSecurityCheck';
import { dnsHealthCheckPlugin } from '../src/lib/plugins/dnsHealthCheck';
import { subdomainTakeoverCheckPlugin } from '../src/lib/plugins/subdomainTakeoverCheck';
import { sensitivePathCheckPlugin } from '../src/lib/plugins/sensitivePathCheck';
import { pluginRegistry } from '../src/lib/plugins/registry';
import { PluginContext } from '../src/lib/plugins/types';
import { dnsClient } from '../src/lib/dnsClient';

test('Wave 1: Zero-Cost Feature Expansion Plugin Suite', async (t) => {

  await t.test('Registry includes all 9 plugins (5 Core + 4 Wave 1)', () => {
    const plugins = pluginRegistry.getAllPlugins();
    assert.ok(plugins.length >= 9, 'Registry should have at least 9 plugins loaded');
    assert.ok(pluginRegistry.getPlugin('email-security-check'));
    assert.ok(pluginRegistry.getPlugin('dns-health-check'));
    assert.ok(pluginRegistry.getPlugin('subdomain-takeover-check'));
    assert.ok(pluginRegistry.getPlugin('sensitive-path-check'));
  });

  await t.test('Plugin 1: Email Security Suite (SPF/DKIM/DMARC/MTA-STS)', async (st) => {
    const mockCtx: PluginContext = {
      safeFetch: async () => new Response('OK', { status: 404 }),
      safeTlsHandshake: async () => ({} as any),
      scanId: 'test-scan',
      organizationId: 'test-org',
      timeoutMs: 4000,
    };

    // Live test on a known domain: google.com
    const result = await emailSecurityCheckPlugin.run({ fqdn: 'google.com', type: 'ROOT_DOMAIN' }, mockCtx);
    assert.equal(result.status, 'COMPLETED');
    assert.ok(result.evidence.length > 0);
    const ev = result.evidence[0].rawObservation;
    assert.equal(ev.spf.present, true, 'google.com must have SPF');
    assert.equal(ev.dmarc.present, true, 'google.com must have DMARC');
    assert.ok(ev.dkim.probedSelectors.length > 0);

    // Assert that no fake finding is emitted on hardened google.com
    const criticalSpf = result.findings.find(f => f.findingCode === 'EMAIL-SPF-PERMISSIVE-PLUS-ALL');
    assert.equal(criticalSpf, undefined, 'google.com must not have +all SPF');
  });

  await t.test('Plugin 2: DNS Health & Zone Integrity', async (st) => {
    const mockCtx: PluginContext = {
      safeFetch: async () => new Response('OK', { status: 404 }),
      safeTlsHandshake: async () => ({} as any),
      scanId: 'test-scan',
      organizationId: 'test-org',
      timeoutMs: 4000,
    };

    const result = await dnsHealthCheckPlugin.run({ fqdn: 'google.com', type: 'ROOT_DOMAIN' }, mockCtx);
    assert.equal(result.status, 'COMPLETED');
    assert.ok(result.evidence.length > 0);
    const ev = result.evidence[0].rawObservation;
    assert.ok(ev.nameservers.configured.length > 0, 'Must identify google.com nameservers');
    assert.equal(ev.nameservers.dangling.length, 0, 'google.com should have no dangling nameservers');
  });

  await t.test('Plugin 3: Subdomain Takeover Detection & Confidence Discipline', async (st) => {
    // 1. Test simulated unclaimed GitHub Pages
    const mockCtxTakeover: PluginContext = {
      safeFetch: async (url: string) => {
        return new Response("There isn't a GitHub Pages site here.", { status: 404 });
      },
      safeTlsHandshake: async () => ({} as any),
      scanId: 'test-scan',
      organizationId: 'test-org',
      timeoutMs: 4000,
    };

    // Mock resilientResolveCname
    const originalResilientResolveCname = dnsClient.resilientResolveCname;
    const originalResilientLookup = dnsClient.resilientLookup;

    (dnsClient as any).resilientResolveCname = async () => ['target-project.github.io'];
    (dnsClient as any).resilientLookup = async () => ({ address: '185.199.108.153', family: 4 });

    try {
      const result = await subdomainTakeoverCheckPlugin.run(
        { fqdn: 'docs.example-abandoned.com', type: 'SUBDOMAIN' },
        mockCtxTakeover
      );

      assert.equal(result.status, 'COMPLETED');
      assert.equal(result.findings.length, 1);
      const takeoverFinding = result.findings[0];
      assert.equal(takeoverFinding.findingCode, 'TAKEOVER-DANGLING-GITHUBPAGES');
      assert.equal(takeoverFinding.severity, 'HIGH');
      assert.equal(takeoverFinding.confidence, 'CONFIRMED', 'Provider signature match must be CONFIRMED');
      assert.ok(takeoverFinding.description.includes("There isn't a GitHub Pages site here"));
    } finally {
      (dnsClient as any).resilientResolveCname = originalResilientResolveCname;
      (dnsClient as any).resilientLookup = originalResilientLookup;
    }

    // 2. Test non-resolving CNAME without body signature (Strict confidence ceiling: MEDIUM)
    const mockCtxDeadCname: PluginContext = {
      safeFetch: async () => { throw new Error('ENOTFOUND'); },
      safeTlsHandshake: async () => ({} as any),
      scanId: 'test-scan',
      organizationId: 'test-org',
      timeoutMs: 4000,
    };

    (dnsClient as any).resilientResolveCname = async () => ['non-existent-cluster-host.cloud.net'];
    (dnsClient as any).resilientLookup = async () => { throw new Error('ENOTFOUND'); };

    try {
      const result = await subdomainTakeoverCheckPlugin.run(
        { fqdn: 'api-dead.example-abandoned.com', type: 'SUBDOMAIN' },
        mockCtxDeadCname
      );

      assert.equal(result.findings.length, 1);
      const finding = result.findings[0];
      assert.equal(finding.findingCode, 'TAKEOVER-UNRESOLVED-CNAME');
      assert.equal(finding.confidence, 'MEDIUM', 'Dead CNAME without proof must be capped at MEDIUM confidence');
    } finally {
      (dnsClient as any).resilientResolveCname = originalResilientResolveCname;
      (dnsClient as any).resilientLookup = originalResilientLookup;
    }
  });

  await t.test('Plugin 4: Sensitive File & Path Exposure (Anti-False-Positive Filtering)', async (st) => {
    // 1. Valid .git/HEAD exposure
    const mockCtxGit: PluginContext = {
      safeFetch: async (url: string) => {
        if (url.includes('/.git/HEAD')) {
          return new Response('ref: refs/heads/main\n', { status: 200 });
        }
        return new Response('Not Found', { status: 404 });
      },
      safeTlsHandshake: async () => ({} as any),
      scanId: 'test-scan',
      organizationId: 'test-org',
      timeoutMs: 4000,
    };

    const gitResult = await sensitivePathCheckPlugin.run({ fqdn: 'vulnerable-site.test', type: 'SUBDOMAIN' }, mockCtxGit);
    const gitFinding = gitResult.findings.find(f => f.findingCode === 'EXPOSURE-GIT-FOLDER');
    assert.ok(gitFinding, 'Must detect exposed .git/HEAD when valid git ref is returned');
    assert.equal(gitFinding?.severity, 'CRITICAL');

    // 2. False-positive defense: Single Page App (SPA) returning 200 OK HTML for /.git/HEAD
    const mockCtxSpaFalsePositive: PluginContext = {
      safeFetch: async () => {
        return new Response('<!DOCTYPE html><html><body>Welcome to My React App</body></html>', { status: 200 });
      },
      safeTlsHandshake: async () => ({} as any),
      scanId: 'test-scan',
      organizationId: 'test-org',
      timeoutMs: 4000,
    };

    const spaResult = await sensitivePathCheckPlugin.run({ fqdn: 'spa-site.test', type: 'SUBDOMAIN' }, mockCtxSpaFalsePositive);
    const falseGitFinding = spaResult.findings.find(f => f.findingCode === 'EXPOSURE-GIT-FOLDER');
    const falseEnvFinding = spaResult.findings.find(f => f.findingCode === 'EXPOSURE-ENV-FILE');
    assert.equal(falseGitFinding, undefined, 'Must reject custom 200 HTML page as .git exposure');
    assert.equal(falseEnvFinding, undefined, 'Must reject custom 200 HTML page as .env exposure');

    // 3. Valid .env credential exposure
    const mockCtxEnv: PluginContext = {
      safeFetch: async (url: string) => {
        if (url.includes('/.env')) {
          return new Response('NODE_ENV=production\nDB_PASSWORD=supersecret_pass123\nAPI_KEY=live_xyz', { status: 200 });
        }
        return new Response('Not Found', { status: 404 });
      },
      safeTlsHandshake: async () => ({} as any),
      scanId: 'test-scan',
      organizationId: 'test-org',
      timeoutMs: 4000,
    };

    const envResult = await sensitivePathCheckPlugin.run({ fqdn: 'vulnerable-site.test', type: 'SUBDOMAIN' }, mockCtxEnv);
    const envFinding = envResult.findings.find(f => f.findingCode === 'EXPOSURE-ENV-FILE');
    assert.ok(envFinding, 'Must detect exposed .env with credentials');
    assert.equal(envFinding?.severity, 'CRITICAL');
  });

});
