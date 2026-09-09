/**
 * PLIŌRA Threat Monitor — GitHub Leaked Credentials & Secrets Analyzer
 * 
 * Searches public GitHub repositories for domain-correlated secrets, credentials,
 * and configuration leaks using structural pattern matching.
 * 
 * Safety & Confidence Discipline (Wave 4 Spec §2):
 * 1. Structural pattern matching (AWS keys, DB strings, API tokens) + domain proximity:
 *    -> HIGH severity, HIGH confidence (SECRET-LEAK-GITHUB-CREDENTIAL).
 *    Strict guard: Kept at HIGH rather than CONFIRMED to account for example/placeholder keys.
 * 2. Bare keyword domain mention without credential shape:
 *    -> INFORMATIONAL severity, LOW confidence (SECRET-LEAK-GITHUB-MENTION).
 * 3. Links public repo URL and file path as actionable evidence.
 * 4. Masks all sensitive secret material in findings and logs.
 * 5. Routes through ExternalApiUsageTracker to respect GitHub's free-tier rate limits.
 */

import { CheckPlugin, PluginContext, PluginResult, FindingSpec, PluginEvidenceSpec } from './types';
import { externalApiTracker } from '@/lib/usage/externalApiTracker';

export interface SecretPatternDef {
  name: string;
  regex: RegExp;
  mask: (match: string) => string;
}

export const STRUCTURAL_SECRET_PATTERNS: SecretPatternDef[] = [
  {
    name: 'AWS Access Key ID',
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    mask: (m) => `${m.slice(0, 4)}************${m.slice(-4)}`,
  },
  {
    name: 'Generic API / Secret Token',
    regex: /(?:api_key|apikey|secret_key|app_secret|client_secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]/gi,
    mask: (m) => `${m.slice(0, 10)}...[REDACTED_SECRET]...${m.slice(-4)}`,
  },
  {
    name: 'Database Connection URI with Credentials',
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_\-]+:([^\s"':@]{6,})@[a-zA-Z0-9_\-\.]+\b/gi,
    mask: (m) => m.replace(/:([^\s"':@]{6,})@/, ':****[REDACTED_PASSWORD]****@'),
  },
  {
    name: 'Private Cryptographic Key',
    regex: /-----BEGIN (?:RSA|OPENSSH|EC|DSA) PRIVATE KEY-----/g,
    mask: () => '-----BEGIN [REDACTED PRIVATE KEY]-----',
  },
];

export function findStructuralSecrets(content: string): Array<{ name: string; masked: string }> {
  const matches: Array<{ name: string; masked: string }> = [];

  for (const pattern of STRUCTURAL_SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    const match = pattern.regex.exec(content);
    if (match) {
      matches.push({
        name: pattern.name,
        masked: pattern.mask(match[0]),
      });
    }
  }

  return matches;
}

export const githubSecretCheckPlugin: CheckPlugin = {
  id: 'github-secret-check',
  name: 'GitHub Leaked Credentials & Secrets Analyzer',
  category: 'SENSITIVE_EXPOSURE',
  defaultConfidence: 'HIGH',

  appliesTo(asset: { fqdn: string; type: string }) {
    return Boolean(asset.fqdn && asset.fqdn.includes('.'));
  },

  async run(asset, ctx: PluginContext): Promise<PluginResult> {
    const startTime = Date.now();
    const findings: FindingSpec[] = [];
    const evidence: PluginEvidenceSpec[] = [];
    const host = asset.fqdn.toLowerCase().trim();

    // Route query through usage tracker to enforce rate limits and daily platform ceilings
    const quotaRes = await externalApiTracker.executeWithQuota(
      'GITHUB_CODE_SEARCH',
      ctx.organizationId,
      async () => {
        const query = encodeURIComponent(`"${host}" (password OR secret OR token OR api_key OR aws_secret_access_key OR "PRIVATE KEY")`);
        const searchUrl = `https://api.github.com/search/code?q=${query}&per_page=5`;

        try {
          const res = await ctx.safeFetch(searchUrl, {
            method: 'GET',
            timeoutMs: 5000,
            headers: {
              Accept: 'application/vnd.github.v3+json',
              'User-Agent': 'PlioraThreatMonitor-SecretScanner/1.0',
            },
          });

          if (res.status === 200) {
            const data = await res.json();
            return { status: 200, items: data.items || [] };
          } else if (res.status === 403 || res.status === 429) {
            return { status: 429, items: [], rateLimited: true };
          }
          return { status: res.status, items: [] };
        } catch (err: any) {
          return { status: 500, items: [], error: err.message };
        }
      }
    );

    // Graceful degradation when quota budget exhausted
    if (!quotaRes.executed) {
      evidence.push({
        checkType: 'LEAKED_CREDENTIAL',
        rawObservation: {
          host,
          provider: 'GITHUB_CODE_SEARCH',
          status: 'SKIPPED_QUOTA_EXHAUSTED',
          reason: quotaRes.reason,
          degradationPolicy: 'Graceful skip — scan pipeline continues without failure',
        },
      });

      return {
        status: 'COMPLETED',
        evidence,
        findings,
        durationMs: Date.now() - startTime,
      };
    }

    const searchData = quotaRes.result;
    const items: any[] = searchData?.items || [];

    for (const item of items) {
      const repoUrl = item.repository?.html_url || 'https://github.com';
      const filePath = item.path || 'unknown/file';
      const fileUrl = item.html_url || `${repoUrl}/blob/master/${filePath}`;
      const repoName = item.repository?.full_name || 'unknown/repo';

      // Look at code fragment text provided by search results
      const snippetText = item.text_matches?.map((m: any) => m.fragment).join('\n') || filePath;
      const structuralSecrets = findStructuralSecrets(snippetText);

      if (structuralSecrets.length > 0) {
        // High confidence finding: structural secret pattern found in code
        for (const sec of structuralSecrets) {
          findings.push({
            category: 'SENSITIVE_EXPOSURE',
            findingCode: 'SECRET-LEAK-GITHUB-CREDENTIAL',
            title: `Exposed ${sec.name} Found in Public GitHub Repository (${repoName})`,
            description: `A public GitHub repository (${repoName}) contains a credential matching ${sec.name} alongside domain reference "${host}" in file "${filePath}". Pattern detected: "${sec.masked}". Public credential leaks allow automated bots to compromise production accounts.`,
            severity: 'HIGH',
            confidence: 'HIGH', // Non-negotiable ceiling: automated pattern match capped at HIGH (guards against synthetic/placeholder keys)
            remediationGuidance: 'Immediately revoke and rotate the exposed secret key. Purge git commit history using git-filter-repo or BFG Repo-Cleaner, and configure GitHub Secret Scanning or pre-commit hooks.',
          });

          evidence.push({
            checkType: 'LEAKED_CREDENTIAL',
            rawObservation: {
              host,
              repository: repoName,
              repoUrl,
              filePath,
              fileUrl,
              secretCategory: sec.name,
              maskedPattern: sec.masked,
              analyzedAt: new Date().toISOString(),
            },
          });
        }
      } else {
        // Low confidence / Informational: domain mentioned in code without credential-shaped strings
        findings.push({
          category: 'SENSITIVE_EXPOSURE',
          findingCode: 'SECRET-LEAK-GITHUB-MENTION',
          title: `Domain Mention in Public GitHub Repository (${repoName})`,
          description: `The domain "${host}" was referenced in public code on GitHub (${repoName} in "${filePath}"). No active credential patterns were detected, but public repository references may indicate configuration exposure or open-source dependencies.`,
          severity: 'INFORMATIONAL',
          confidence: 'LOW',
          remediationGuidance: 'Review the public repository reference to verify whether internal infrastructure or staging domains are unintentionally documented in open-source projects.',
        });

        evidence.push({
          checkType: 'LEAKED_CREDENTIAL',
          rawObservation: {
            host,
            repository: repoName,
            repoUrl,
            filePath,
            fileUrl,
            isCredentialDetected: false,
          },
        });
      }
    }

    if (findings.length === 0) {
      evidence.push({
        checkType: 'LEAKED_CREDENTIAL',
        rawObservation: {
          host,
          provider: 'GITHUB_CODE_SEARCH',
          itemsFound: 0,
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
