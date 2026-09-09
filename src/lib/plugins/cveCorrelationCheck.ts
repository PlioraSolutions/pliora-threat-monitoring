import { CheckPlugin, PluginContext, PluginResult, FindingSpec, PluginEvidenceSpec } from './types';
import { correlateTechnologyCves } from '@/lib/cve/cveCorrelation';

export const cveCorrelationCheckPlugin: CheckPlugin = {
  id: 'cve-correlation-check',
  name: 'CVE & Known Vulnerability Correlation Analyzer',
  category: 'TECH_VERSION',
  defaultConfidence: 'MEDIUM', // Non-negotiable ceiling: version matches are hypotheses, not confirmed exploitation

  appliesTo(asset: { fqdn: string; type: string }) {
    return Boolean(asset.fqdn && asset.fqdn.includes('.'));
  },

  async run(asset, ctx: PluginContext): Promise<PluginResult> {
    const startTime = Date.now();
    const findings: FindingSpec[] = [];
    const evidence: PluginEvidenceSpec[] = [];

    // Probe server for headers & version indicators
    let serverHeader: string | null = null;
    let xPoweredBy: string | null = null;

    try {
      const res = await ctx.safeFetch(`https://${asset.fqdn}`, {
        method: 'HEAD',
        redirect: 'manual',
        timeoutMs: Math.min(3000, ctx.timeoutMs ?? 3000),
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; PlioraThreatMonitor/1.0; +https://pliora.io)',
        },
      });

      serverHeader = res.headers.get('server');
      xPoweredBy = res.headers.get('x-powered-by');
    } catch {
      try {
        const resHttp = await ctx.safeFetch(`http://${asset.fqdn}`, {
          method: 'HEAD',
          redirect: 'manual',
          timeoutMs: Math.min(3000, ctx.timeoutMs ?? 3000),
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; PlioraThreatMonitor/1.0; +https://pliora.io)',
          },
        });
        serverHeader = resHttp.headers.get('server');
        xPoweredBy = resHttp.headers.get('x-powered-by');
      } catch {}
    }

    const targetsToCorrelate: Array<{ tech: string; version?: string }> = [];

    if (serverHeader) {
      const parts = serverHeader.trim().split('/');
      if (parts.length >= 2) {
        targetsToCorrelate.push({ tech: parts[0], version: parts[1].split(' ')[0] });
      }
    }

    if (xPoweredBy) {
      const parts = xPoweredBy.trim().split('/');
      if (parts.length >= 2) {
        targetsToCorrelate.push({ tech: parts[0], version: parts[1].split(' ')[0] });
      }
    }

    for (const target of targetsToCorrelate) {
      const cveMatches = correlateTechnologyCves(target.tech, target.version, false);

      for (const match of cveMatches) {
        // ENFORCE HARD GUARD (§A.2 DoD): Fingerprint-only CVE match MUST NOT exceed MEDIUM confidence
        const safeConfidence = match.isBehaviorallyCorroborated ? 'HIGH' : 'MEDIUM';

        findings.push({
          category: 'TECH_VERSION',
          findingCode: `CVE-${match.cveId.replace(/[^A-Z0-9-]/gi, '')}`,
          title: match.title,
          description: match.description,
          severity: match.severity,
          confidence: safeConfidence,
          remediationGuidance: match.remediation,
        });

        evidence.push({
          checkType: 'TECH_FINGERPRINT',
          rawObservation: {
            cveId: match.cveId,
            technology: match.technology,
            detectedVersion: target.version,
            cvssScore: match.cvssScore,
            epssScore: match.epssScore,
            advisoryUrl: match.advisoryUrl,
            analyzedAt: new Date().toISOString(),
          },
        });
      }
    }

    return {
      status: 'COMPLETED',
      evidence,
      findings,
      durationMs: Date.now() - startTime,
    };
  },
};
