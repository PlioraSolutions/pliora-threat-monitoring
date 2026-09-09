import test from 'node:test';
import assert from 'node:assert/strict';
import { pluginRegistry } from '../src/lib/plugins/registry';
import { breachExposureCheckPlugin, maskEmail } from '../src/lib/plugins/breachExposureCheck';
import { githubSecretCheckPlugin, findStructuralSecrets } from '../src/lib/plugins/githubSecretCheck';
import { pasteSecretCheckPlugin } from '../src/lib/plugins/pasteSecretCheck';
import { externalApiTracker } from '../src/lib/usage/externalApiTracker';
import { REMEDIATION_LIBRARY, validateRemediationSteps } from '../src/lib/ai/remediationLibrary';
import { shouldAlertOnFinding } from '../src/lib/alerts/rules';
import { PluginContext } from '../src/lib/plugins/types';

test('Wave 4: Leaked Credential & Secret Exposure Plugin Suite', async (t) => {

  // 1. Registry Test
  await t.test('Registry includes all 17 plugins (5 Core + 4 Wave 1 + 3 Wave 2 + 2 Wave 3 + 3 Wave 4)', () => {
    const plugins = pluginRegistry.getAllPlugins();
    assert.equal(plugins.length, 17, 'Registry should have exactly 17 plugins loaded');
    assert.ok(pluginRegistry.getPlugin('breach-exposure-check'), 'breach-exposure-check should be registered');
    assert.ok(pluginRegistry.getPlugin('github-secret-check'), 'github-secret-check should be registered');
    assert.ok(pluginRegistry.getPlugin('paste-secret-check'), 'paste-secret-check should be registered');
  });

  // 2. Email Masking Helper
  await t.test('Email masking helper redacts username for privacy', () => {
    assert.equal(maskEmail('admin@pliora.io'), 'ad***@pliora.io');
    assert.equal(maskEmail('security-officer@company.com'), 'se***@company.com');
  });

  // 3. Structural Secret Pattern Matching
  await t.test('Structural secret pattern matcher detects keys and sanitizes values', () => {
    const awsSample = 'const awsKey = "AKIAIOSFODNN7EXAMPLE"; // AWS key';
    const awsMatches = findStructuralSecrets(awsSample);
    assert.equal(awsMatches.length, 1);
    assert.equal(awsMatches[0].name, 'AWS Access Key ID');
    assert.equal(awsMatches[0].masked, 'AKIA************MPLE');

    const dbSample = 'postgres://dbuser:superSecretPass123@db.internal.corp:5432/appdb';
    const dbMatches = findStructuralSecrets(dbSample);
    assert.equal(dbMatches.length, 1);
    assert.equal(dbMatches[0].name, 'Database Connection URI with Credentials');
    assert.ok(dbMatches[0].masked.includes('[REDACTED_PASSWORD]'));

    const cleanSample = 'Welcome to the documentation for pliora.io backend services.';
    const cleanMatches = findStructuralSecrets(cleanSample);
    assert.equal(cleanMatches.length, 0);
  });

  // 4. Breach-Exposure Plugin: Confirmed Breach Match & Zero-Raw-Password Invariant
  await t.test('Breach Exposure: Confirmed public breach -> HIGH severity, CONFIRMED confidence, ZERO raw password storage', async () => {
    externalApiTracker.resetForTesting();

    const mockCtx: PluginContext = {
      safeFetch: async (url: string) => {
        if (url.includes('xposedornot.com') || url.includes('breachedaccount')) {
          return new Response(JSON.stringify({
            breaches: [
              {
                name: 'CorporateDataDump2024',
                title: 'Corporate Data Dump 2024',
                breachDate: '2024-03-15',
                dataClasses: ['Email addresses', 'Passwords', 'IP addresses'],
                pwnCount: 154000,
              },
            ],
          }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        return new Response('Not found', { status: 404 });
      },
      safeTlsHandshake: async () => ({} as any),
      organizationId: 'org-breach-test',
    };

    const res = await breachExposureCheckPlugin.run(
      { fqdn: 'targetcorp.com', type: 'DOMAIN', contactEmail: 'security@targetcorp.com' } as any,
      mockCtx
    );

    assert.equal(res.status, 'COMPLETED');
    const breachFinding = res.findings.find((f) => f.findingCode === 'BREACH-EXPOSURE-EMAIL-FOUND');
    assert.ok(breachFinding, 'Must emit BREACH-EXPOSURE-EMAIL-FOUND finding');
    assert.equal(breachFinding.severity, 'HIGH');
    assert.equal(breachFinding.confidence, 'CONFIRMED');

    // CRITICAL SECURITY INVARIANT TEST:
    // Assert NO raw passwords or password hashes appear anywhere in findings or evidence
    const fullSerialized = JSON.stringify(res);
    assert.ok(!fullSerialized.includes('plaintext'), 'No plaintext passwords allowed');
    assert.ok(!fullSerialized.includes('superSecret'), 'No raw credentials allowed');
    assert.ok(fullSerialized.includes('Zero raw passwords'), 'Must include security credential protection notice');
  });

  // 5. Breach-Exposure Plugin: Graceful Degradation on Quota Exhaustion
  await t.test('Breach Exposure: Degrades gracefully when external API quota is exhausted', async () => {
    externalApiTracker.resetForTesting();
    // Artificially exhaust BREACH_DIRECTORY quota
    externalApiTracker.setLimits('BREACH_DIRECTORY', { requestsPerMinute: 0, requestsPerDay: 0 });

    let fetchAttempted = false;
    const mockCtx: PluginContext = {
      safeFetch: async () => {
        fetchAttempted = true;
        return new Response('{}', { status: 200 });
      },
      safeTlsHandshake: async () => ({} as any),
      organizationId: 'org-exhausted',
    };

    const res = await breachExposureCheckPlugin.run({ fqdn: 'targetcorp.com', type: 'DOMAIN' }, mockCtx);

    assert.equal(fetchAttempted, false, 'External API call should not be made when quota is exhausted');
    assert.equal(res.status, 'COMPLETED', 'Scan should complete gracefully without throwing');
    assert.equal(res.findings.length, 0, 'No false findings when degraded');
    const skippedEvidence = res.evidence.find((e) => e.rawObservation?.status === 'SKIPPED_QUOTA_EXHAUSTED');
    assert.ok(skippedEvidence, 'Must record degradation evidence');
  });

  // 6. GitHub Secret Exposure: Structural Key vs Bare Domain Mention
  await t.test('GitHub Secret Exposure: Structural AWS key -> HIGH/HIGH; Bare mention -> INFORMATIONAL/LOW', async () => {
    externalApiTracker.resetForTesting();

    const mockCtx: PluginContext = {
      safeFetch: async (url: string) => {
        if (url.includes('api.github.com/search/code')) {
          return new Response(JSON.stringify({
            items: [
              {
                path: 'config/aws.ts',
                html_url: 'https://github.com/leaker/repo/blob/main/config/aws.ts',
                repository: {
                  full_name: 'leaker/repo',
                  html_url: 'https://github.com/leaker/repo',
                },
                text_matches: [
                  {
                    fragment: 'const domain = "mycompany.com";\nconst key = "AKIAIOSFODNN7EXAMPLE";\n',
                  },
                ],
              },
              {
                path: 'README.md',
                html_url: 'https://github.com/other/docs/blob/main/README.md',
                repository: {
                  full_name: 'other/docs',
                  html_url: 'https://github.com/other/docs',
                },
                text_matches: [
                  {
                    fragment: 'See our partners at mycompany.com for more info.',
                  },
                ],
              },
            ],
          }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        return new Response('Not found', { status: 404 });
      },
      safeTlsHandshake: async () => ({} as any),
      organizationId: 'org-gh-test',
    };

    const res = await githubSecretCheckPlugin.run({ fqdn: 'mycompany.com', type: 'DOMAIN' }, mockCtx);
    assert.equal(res.status, 'COMPLETED');

    const credFinding = res.findings.find((f) => f.findingCode === 'SECRET-LEAK-GITHUB-CREDENTIAL');
    assert.ok(credFinding, 'Should detect structural AWS key in repo code');
    assert.equal(credFinding.severity, 'HIGH');
    assert.equal(credFinding.confidence, 'HIGH', 'Confidence ceiling must be HIGH to account for test keys');
    assert.ok(credFinding.description.includes('AKIA************MPLE'), 'Must mask credential string');

    const mentionFinding = res.findings.find((f) => f.findingCode === 'SECRET-LEAK-GITHUB-MENTION');
    assert.ok(mentionFinding, 'Should detect bare domain mention in README');
    assert.equal(mentionFinding.severity, 'INFORMATIONAL');
    assert.equal(mentionFinding.confidence, 'LOW');
  });

  // 7. Paste-Site Monitoring: Best-Effort Framing & MEDIUM Confidence Ceiling
  await t.test('Paste Site Monitoring: Honest best-effort framing & MEDIUM confidence ceiling', async () => {
    externalApiTracker.resetForTesting();

    const mockCtx: PluginContext = {
      safeFetch: async (url: string) => {
        if (url.includes('psbdmp.ws') || url.includes('paste')) {
          return new Response(JSON.stringify({
            data: [
              {
                id: 'paste_xyz123',
                time: '2026-04-01 10:00:00',
                url: 'https://pastebin.com/paste_xyz123',
              },
            ],
          }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        return new Response('Not found', { status: 404 });
      },
      safeTlsHandshake: async () => ({} as any),
      organizationId: 'org-paste-test',
    };

    const res = await pasteSecretCheckPlugin.run({ fqdn: 'targetdomain.com', type: 'DOMAIN' }, mockCtx);
    assert.equal(res.status, 'COMPLETED');

    const pasteFinding = res.findings.find((f) => f.findingCode === 'SECRET-LEAK-PASTE-MATCH');
    assert.ok(pasteFinding, 'Should detect paste archive entry');
    assert.equal(pasteFinding.severity, 'MEDIUM');
    assert.equal(pasteFinding.confidence, 'MEDIUM', 'Confidence must be capped strictly at MEDIUM');
    assert.ok(pasteFinding.description.includes('best-effort'), 'Must include honest best-effort caveat in customer copy');
  });

  // 8. AI Grounding Remediation Library Coverage
  await t.test('AI Grounding Library: Covers all Wave 4 codes with v1.3.0 and validated steps', () => {
    const wave4Codes = [
      'SECRET-LEAK-GITHUB-CREDENTIAL',
      'SECRET-LEAK-GITHUB-MENTION',
      'SECRET-LEAK-PASTE-MATCH',
      'BREACH-EXPOSURE-EMAIL-FOUND',
    ];

    for (const code of wave4Codes) {
      const entry = REMEDIATION_LIBRARY[code];
      assert.ok(entry, `Remediation entry must exist for ${code}`);
      assert.equal(entry.version, '1.3.0', `Version must be 1.3.0 for ${code}`);
      assert.ok(entry.approvedSteps.length >= 3, `Must provide at least 3 vetted steps for ${code}`);

      // Valid steps pass
      const val = validateRemediationSteps(code, entry.approvedSteps);
      assert.equal(val.valid, true);

      // Hallucinated step rejected
      const invalid = validateRemediationSteps(code, ['Install a botnet payload on customer servers.']);
      assert.equal(invalid.valid, false);
      assert.equal(invalid.rejectedSteps.length, 1);
    }
  });

  // 9. Alert Engine Integration
  await t.test('Alert Rules Engine: High/Confirmed leaked secrets trigger alerts; Informational mentions are suppressed', () => {
    // 9a. Breached account (HIGH severity, CONFIRMED confidence, riskScore 85) -> Must alert
    const breachAlert = shouldAlertOnFinding(
      { severity: 'HIGH', confidence: 'CONFIRMED', riskScore: 85 },
      { importance: 'CRITICAL', type: 'ROOT_DOMAIN' }
    );
    assert.equal(breachAlert.shouldAlert, true);
    assert.equal(breachAlert.alertType, 'NEW_HIGH_FINDING');

    // 9b. GitHub credential leak (HIGH severity, HIGH confidence, riskScore 80) -> Must alert
    const ghCredAlert = shouldAlertOnFinding(
      { severity: 'HIGH', confidence: 'HIGH', riskScore: 80 },
      { importance: 'HIGH', type: 'ROOT_DOMAIN' }
    );
    assert.equal(ghCredAlert.shouldAlert, true);
    assert.equal(ghCredAlert.alertType, 'NEW_HIGH_FINDING');

    // 9c. GitHub bare mention (INFORMATIONAL severity, LOW confidence, riskScore 10) -> Must suppress
    const ghMentionAlert = shouldAlertOnFinding(
      { severity: 'INFORMATIONAL', confidence: 'LOW', riskScore: 10 },
      { importance: 'NORMAL', type: 'ROOT_DOMAIN' }
    );
    assert.equal(ghMentionAlert.shouldAlert, false, 'Informational mentions must never trigger an alert');
  });

});
