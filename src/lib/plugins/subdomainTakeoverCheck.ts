import { CheckPlugin, PluginContext, PluginResult, FindingSpec, PluginEvidenceSpec } from './types';
import { resilientResolveCname, resilientLookup } from '@/lib/dnsClient';

interface CloudProviderFingerprint {
  name: string;
  cnamePatterns: string[];
  responseSignatures: string[];
  severity: 'CRITICAL' | 'HIGH';
}

const CLOUD_TAKEOVER_FINGERPRINTS: CloudProviderFingerprint[] = [
  {
    name: 'GitHub Pages',
    cnamePatterns: ['github.io'],
    responseSignatures: [
      "There isn't a GitHub Pages site here",
      "For root URLs (like http://example.com/) you must provide an index.html file",
    ],
    severity: 'HIGH',
  },
  {
    name: 'Amazon Web Services S3',
    cnamePatterns: ['s3.amazonaws.com', 's3-website', 's3.dualstack'],
    responseSignatures: [
      'NoSuchBucket',
      'The specified bucket does not exist',
    ],
    severity: 'CRITICAL',
  },
  {
    name: 'Heroku',
    cnamePatterns: ['herokudns.com', 'herokuapp.com'],
    responseSignatures: [
      'No such app',
      'herokucdn.com/error-pages/no-such-app.html',
    ],
    severity: 'HIGH',
  },
  {
    name: 'Netlify',
    cnamePatterns: ['netlify.app', 'netlify.com'],
    responseSignatures: [
      'Not Found - Request ID:',
      'Page not found - Netlify',
    ],
    severity: 'HIGH',
  },
  {
    name: 'Vercel',
    cnamePatterns: ['cname.vercel-dns.com', 'vercel-dns.com'],
    responseSignatures: [
      'The deployment could not be found on Vercel',
      'DEPLOYMENT_NOT_FOUND',
      '404: NOT_FOUND',
    ],
    severity: 'HIGH',
  },
  {
    name: 'Microsoft Azure Web App',
    cnamePatterns: ['azurewebsites.net', 'cloudapp.azure.com', 'trafficmanager.net'],
    responseSignatures: [
      '404 Web Site not found',
      'Microsoft-Azure-Application-Gateway',
    ],
    severity: 'HIGH',
  },
  {
    name: 'Fastly CDN',
    cnamePatterns: ['fastly.net', 'fastlylb.net'],
    responseSignatures: [
      'Fastly error: unknown domain',
    ],
    severity: 'HIGH',
  },
];

export const subdomainTakeoverCheckPlugin: CheckPlugin = {
  id: 'subdomain-takeover-check',
  name: 'Subdomain Takeover & Dangling Cloud Resource Analyzer',
  category: 'SUBDOMAIN_TAKEOVER',
  defaultConfidence: 'CONFIRMED',

  appliesTo(asset: { fqdn: string; type: string }) {
    // Primarily inspects subdomains that could have CNAME pointers
    return Boolean(asset.fqdn && asset.fqdn.includes('.'));
  },

  async run(asset, ctx: PluginContext): Promise<PluginResult> {
    const startTime = Date.now();
    const findings: FindingSpec[] = [];
    const evidence: PluginEvidenceSpec[] = [];
    const host = asset.fqdn.toLowerCase().trim();

    let cnames: string[] = [];
    try {
      cnames = await resilientResolveCname(host);
    } catch {
      // Asset has no CNAME (uses A/AAAA direct mapping)
    }

    if (!cnames || cnames.length === 0) {
      return {
        status: 'COMPLETED',
        evidence: [],
        findings: [],
        durationMs: Date.now() - startTime,
      };
    }

    for (const cnameTarget of cnames) {
      const lowerCname = cnameTarget.toLowerCase();

      // Check if CNAME matches a known cloud provider pattern
      const matchedProvider = CLOUD_TAKEOVER_FINGERPRINTS.find((prov) =>
        prov.cnamePatterns.some((pat) => lowerCname.includes(pat))
      );

      // Check if CNAME target destination actually resolves via DNS
      let cnameResolves = true;
      try {
        await resilientLookup(cnameTarget);
      } catch {
        cnameResolves = false;
      }

      let responseBody = '';
      let statusCode = 0;

      if (cnameResolves) {
        try {
          const res = await ctx.safeFetch(`https://${host}`, {
            timeoutMs: 4000,
            headers: {
              'User-Agent': 'Mozilla/5.0 (compatible; PlioraTakeoverDetector/1.0)',
            },
          });
          statusCode = res.status;
          responseBody = await res.text();
        } catch {
          try {
            const resHttp = await ctx.safeFetch(`http://${host}`, {
              timeoutMs: 4000,
              headers: {
                'User-Agent': 'Mozilla/5.0 (compatible; PlioraTakeoverDetector/1.0)',
              },
            });
            statusCode = resHttp.status;
            responseBody = await resHttp.text();
          } catch {}
        }
      }

      // Check for unclaimed provider response signatures
      if (matchedProvider && responseBody) {
        const signatureMatch = matchedProvider.responseSignatures.find((sig) =>
          responseBody.includes(sig)
        );

        if (signatureMatch) {
          findings.push({
            category: 'SUBDOMAIN_TAKEOVER',
            findingCode: `TAKEOVER-DANGLING-${matchedProvider.name.toUpperCase().replace(/[^A-Z0-9]/g, '')}`,
            title: `Critical Subdomain Takeover Vulnerability: ${matchedProvider.name} (${host})`,
            description: `The subdomain ${host} is CNAME-delegated to "${cnameTarget}" on ${matchedProvider.name}, but the target resource has been deleted or abandoned. The server returned the signature: "${signatureMatch}". An attacker can register this resource on ${matchedProvider.name} and serve malicious content, steal cookies, or execute phishing on ${host}.`,
            severity: matchedProvider.severity,
            confidence: 'CONFIRMED',
            remediationGuidance: `Remove the CNAME DNS record for ${host} or claim the corresponding resource name on ${matchedProvider.name}.`,
          });
        }
      } else if (!cnameResolves) {
        // Dangling CNAME to completely non-existent external host (strictly capped at MEDIUM confidence)
        findings.push({
          category: 'SUBDOMAIN_TAKEOVER',
          findingCode: 'TAKEOVER-UNRESOLVED-CNAME',
          title: `Dangling CNAME to Non-Resolving Destination (${cnameTarget})`,
          description: `The subdomain ${host} points to CNAME "${cnameTarget}", which fails to resolve in DNS. If the destination domain was abandoned or expired, an adversary could purchase it to hijack traffic to ${host}.`,
          severity: 'MEDIUM',
          confidence: 'MEDIUM', // Strict confidence ceiling per DoD
          remediationGuidance: `Remove the dangling CNAME DNS entry pointing to unresolvable host ${cnameTarget}.`,
        });
      }

      evidence.push({
        checkType: 'SUBDOMAIN_TAKEOVER',
        rawObservation: {
          host,
          cnameTarget,
          matchedProvider: matchedProvider?.name || null,
          cnameResolves,
          probedStatusCode: statusCode,
          signatureObserved: Boolean(findings.length > 0),
          analyzedAt: new Date().toISOString(),
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
