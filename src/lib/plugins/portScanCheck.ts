import { CheckPlugin, PluginContext, PluginResult, FindingSpec, PluginEvidenceSpec } from './types';

const COMMON_WEB_PORTS = [
  { port: 80, scheme: 'http', isStandard: true, name: 'HTTP Standard' },
  { port: 443, scheme: 'https', isStandard: true, name: 'HTTPS Standard' },
  { port: 8080, scheme: 'http', isStandard: false, name: 'HTTP Alternative / Admin Interface' },
  { port: 8443, scheme: 'https', isStandard: false, name: 'HTTPS Alternative / Management Interface' },
];

export const portScanCheckPlugin: CheckPlugin = {
  id: 'port-scan-check',
  name: 'Open Port & Service Banner Scanner',
  category: 'EXPOSED_SERVICES',
  defaultConfidence: 'MEDIUM', // Non-negotiable ceiling (§A.1): an open port is a fact; exploitability is not proven without corroborating evidence

  appliesTo(asset: { fqdn: string; type: string }) {
    return Boolean(asset.fqdn && asset.fqdn.includes('.'));
  },

  async run(asset, ctx: PluginContext): Promise<PluginResult> {
    const startTime = Date.now();
    const findings: FindingSpec[] = [];
    const evidence: PluginEvidenceSpec[] = [];
    const probedResults: Array<{ port: number; status: 'OPEN' | 'CLOSED' | 'TIMEOUT'; service?: string; banner?: string }> = [];

    for (const portDef of COMMON_WEB_PORTS) {
      const targetUrl = `${portDef.scheme}://${asset.fqdn}:${portDef.port}`;
      try {
        const res = await ctx.safeFetch(targetUrl, {
          method: 'GET',
          redirect: 'manual',
          timeoutMs: Math.min(2500, ctx.timeoutMs ?? 2500),
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; PlioraThreatMonitor/1.0; +https://pliora.io)',
            Accept: '*/*',
          },
        });

        const serverHeader = res.headers.get('server') || undefined;
        probedResults.push({
          port: portDef.port,
          status: 'OPEN',
          service: portDef.name,
          banner: serverHeader,
        });

        // Non-standard ports (8080, 8443) exposed directly on public internet
        if (!portDef.isStandard) {
          findings.push({
            category: 'EXPOSED_SERVICES',
            findingCode: `PORT-EXPOSED-${portDef.port}`,
            title: `Non-Standard Web Service Port Open: Port ${portDef.port} (${portDef.name})`,
            description: `The host exposed an active service on port ${portDef.port} (${targetUrl}). Non-standard web ports frequently host unmonitored development instances, administration dashboards, or staging APIs with weaker access controls.`,
            severity: 'MEDIUM',
            confidence: 'MEDIUM', // Strictly capped at MEDIUM per §A.1 DoD
            remediationGuidance: `Restrict access to port ${portDef.port} using firewall or network security group rules. If an administrative portal or development instance is hosted here, place it behind a VPN or internal load balancer.`,
          });
        }
      } catch (err: any) {
        const isTimeout = err.message?.includes('timeout') || err.message?.includes('Abort');
        probedResults.push({
          port: portDef.port,
          status: isTimeout ? 'TIMEOUT' : 'CLOSED',
        });
      }
    }

    evidence.push({
      checkType: 'SERVICE_BANNER',
      rawObservation: {
        host: asset.fqdn,
        probedPorts: probedResults,
        scannedAt: new Date().toISOString(),
      },
    });

    return {
      status: 'COMPLETED',
      evidence,
      findings,
      durationMs: Date.now() - startTime,
    };
  },
};
