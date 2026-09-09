/**
 * PLIŌRA Threat Monitor — Public Paste-Site Exposure Analyzer
 * 
 * Searches public paste repositories and dumps for domain references,
 * leaked configuration fragments, and exposed credentials.
 * 
 * Operational & Confidence Framing (Wave 4 Spec §3):
 * 1. HONEST BEST-EFFORT FRAMING:
 *    Paste-site coverage is explicitly framed as best-effort monitoring rather
 *    than guaranteed dark-web surveillance. Public paste sources are ephemeral
 *    and non-exhaustive; this limitation is directly communicated in customer-facing findings.
 * 2. STRICT CONFIDENCE CEILING:
 *    All findings are strictly capped at MEDIUM confidence (SECRET-LEAK-PASTE-MATCH)
 *    because paste-site content is inherently unstructured and unverifiable compared
 *    to direct repository commits or DNS facts.
 * 3. USAGE & COST BOUNDARY:
 *    Routes through ExternalApiUsageTracker to observe rate limits and platform budgets.
 */

import { CheckPlugin, PluginContext, PluginResult, FindingSpec, PluginEvidenceSpec } from './types';
import { externalApiTracker } from '@/lib/usage/externalApiTracker';

export const pasteSecretCheckPlugin: CheckPlugin = {
  id: 'paste-secret-check',
  name: 'Public Paste-Site Exposure Analyzer',
  category: 'SENSITIVE_EXPOSURE',
  defaultConfidence: 'MEDIUM', // Strict ceiling: Unstructured third-party paste data

  appliesTo(asset: { fqdn: string; type: string }) {
    return Boolean(asset.fqdn && asset.fqdn.includes('.'));
  },

  async run(asset, ctx: PluginContext): Promise<PluginResult> {
    const startTime = Date.now();
    const findings: FindingSpec[] = [];
    const evidence: PluginEvidenceSpec[] = [];
    const host = asset.fqdn.toLowerCase().trim();

    // Route query through usage tracker
    const quotaRes = await externalApiTracker.executeWithQuota(
      'PASTE_AGGREGATOR',
      ctx.organizationId,
      async () => {
        const searchUrl = `https://psbdmp.ws/api/v3/search/${encodeURIComponent(host)}`;
        try {
          const res = await ctx.safeFetch(searchUrl, {
            method: 'GET',
            timeoutMs: 4000,
            headers: {
              Accept: 'application/json',
              'User-Agent': 'PlioraThreatMonitor-PasteScanner/1.0',
            },
          });

          if (res.status === 200) {
            const data = await res.json();
            const pastes = Array.isArray(data?.data) ? data.data : (Array.isArray(data) ? data : []);
            return { status: 200, pastes };
          } else if (res.status === 404) {
            return { status: 404, pastes: [] };
          }
          return { status: res.status, pastes: [] };
        } catch (err: any) {
          return { status: 500, pastes: [], error: err.message };
        }
      }
    );

    // Graceful degradation when quota budget reached
    if (!quotaRes.executed) {
      evidence.push({
        checkType: 'LEAKED_CREDENTIAL',
        rawObservation: {
          host,
          provider: 'PASTE_AGGREGATOR',
          status: 'SKIPPED_QUOTA_EXHAUSTED',
          reason: quotaRes.reason,
          coverageNotice: 'Best-effort monitoring: Paste checks are periodic and non-exhaustive.',
        },
      });

      return {
        status: 'COMPLETED',
        evidence,
        findings,
        durationMs: Date.now() - startTime,
      };
    }

    const pasteData = quotaRes.result;
    const pastes: any[] = pasteData?.pastes || [];

    for (const paste of pastes.slice(0, 5)) {
      const pasteId = paste.id || paste.key || 'unknown';
      const pasteDate = paste.time || paste.date || new Date().toISOString();
      const pasteUrl = paste.url || `https://pastebin.com/${pasteId}`;

      findings.push({
        category: 'SENSITIVE_EXPOSURE',
        findingCode: 'SECRET-LEAK-PASTE-MATCH',
        title: `Domain Identifier Detected in Public Paste Archive (${pasteId})`,
        description: `References to "${host}" were discovered in a public paste dump (${pasteUrl}, logged: ${pasteDate}). Public paste sites are frequently used by threat actors to dump leaked database dumps, API credentials, or internal configuration logs. Note: This check provides best-effort visibility across public archives and does not guarantee complete coverage of ephemeral dumps.`,
        severity: 'MEDIUM',
        confidence: 'MEDIUM', // Strict ceiling: Option 4 §3
        remediationGuidance: 'Review the referenced paste content, revoke any compromised API tokens or database passwords contained within, and monitor internal systems for abnormal authentication attempts.',
      });

      evidence.push({
        checkType: 'LEAKED_CREDENTIAL',
        rawObservation: {
          host,
          pasteId,
          pasteUrl,
          pasteDate,
          coverageNotice: 'Best-effort coverage of public paste repositories. Monitoring is non-exhaustive.',
          analyzedAt: new Date().toISOString(),
        },
      });
    }

    if (findings.length === 0) {
      evidence.push({
        checkType: 'LEAKED_CREDENTIAL',
        rawObservation: {
          host,
          provider: 'PASTE_AGGREGATOR',
          matchesFound: 0,
          coverageNotice: 'Best-effort coverage of public paste repositories. Monitoring is non-exhaustive.',
          scannedAt: new Date().toISOString(),
        },
      });
    }

    return {
      status: 'COMPLETED',
      evidence,
      findings,
      durationMs: Date.now() - startTime,
    };
  },
};
