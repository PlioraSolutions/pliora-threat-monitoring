import { CheckPlugin, PluginContext, PluginResult, FindingSpec, PluginEvidenceSpec } from './types';
import {
  resilientResolveCaa,
  resilientResolveNs,
  resilientResolveSoa,
  resilientLookup,
  resilientResolver,
} from '@/lib/dnsClient';

export const dnsHealthCheckPlugin: CheckPlugin = {
  id: 'dns-health-check',
  name: 'DNS Health, DNSSEC & Zone Integrity Analyzer',
  category: 'DNS_HEALTH',
  defaultConfidence: 'CONFIRMED',

  appliesTo(asset: { fqdn: string; type: string }) {
    return Boolean(asset.fqdn && asset.fqdn.includes('.'));
  },

  async run(asset, ctx: PluginContext): Promise<PluginResult> {
    const startTime = Date.now();
    const findings: FindingSpec[] = [];
    const evidence: PluginEvidenceSpec[] = [];
    const host = asset.fqdn.toLowerCase().trim();

    // 1. CAA Record Check
    let caaRecords: any[] = [];
    try {
      caaRecords = await resilientResolveCaa(host);
    } catch {
      // CAA missing is standard for many unhardened domains
    }

    if (!caaRecords || caaRecords.length === 0) {
      findings.push({
        category: 'DNS_HEALTH',
        findingCode: 'DNS-CAA-MISSING',
        title: 'Missing CAA (Certificate Authority Authorization) Record',
        description: `No CAA records published for ${host}. Without CAA restrictions, any publicly trusted Certificate Authority can issue TLS certificates for this domain.`,
        severity: 'LOW',
        confidence: 'CONFIRMED',
        remediationGuidance: 'Add CAA records to restrict certificate issuance to your designated CAs (e.g. 0 issue "letsencrypt.org").',
      });
    }

    // 2. Nameserver Health & Dangling Delegation Check
    let nameservers: string[] = [];
    const danglingNs: string[] = [];

    try {
      nameservers = await resilientResolveNs(host);
      await Promise.all(
        nameservers.map(async (ns) => {
          try {
            await resilientLookup(ns);
          } catch {
            danglingNs.push(ns);
          }
        })
      );
    } catch {
      // Subdomains may not have explicit NS delegation
    }

    if (danglingNs.length > 0) {
      findings.push({
        category: 'DNS_HEALTH',
        findingCode: 'DNS-DANGLING-NS-DELEGATION',
        title: `Dangling Nameserver Delegation Detected (${danglingNs.join(', ')})`,
        description: `The domain ${host} delegates DNS authority to nameservers that do not resolve: ${danglingNs.join(', ')}. Threat actors can register expired or abandoned nameserver domains to achieve complete DNS zone takeover.`,
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        remediationGuidance: 'Immediately remove non-resolving nameservers from your domain registrar and DNS configuration.',
      });
    }

    // 3. DNSSEC Check
    let dnssecConfigured = false;
    try {
      // Probing SOA / RRSIG
      const soa = await resilientResolveSoa(host);
      if (soa) {
        // In Node, we check if DNSKEY / RRSIG exists
        try {
          const rawAny = await (resilientResolver.resolve as any)(host, 'DNSKEY');
          if (Array.isArray(rawAny) && rawAny.length > 0) {
            dnssecConfigured = true;
          }
        } catch {}
      }
    } catch {}

    if (!dnssecConfigured) {
      findings.push({
        category: 'DNS_HEALTH',
        findingCode: 'DNS-DNSSEC-MISSING',
        title: 'DNSSEC Cryptographic Signing Disabled',
        description: `Domain Name System Security Extensions (DNSSEC) are not enabled on ${host}. DNS responses are unauthenticated and vulnerable to DNS cache poisoning and spoofing.`,
        severity: 'LOW',
        confidence: 'CONFIRMED',
        remediationGuidance: 'Enable DNSSEC with your DNS provider (e.g. Cloudflare, Route53) and add the DS record to your domain registrar.',
      });
    }

    // 4. Wildcard DNS Misuse Detection
    let wildcardResolves = false;
    let wildcardIp: string | null = null;
    const randomSubdomain = `pliora-audit-${Math.random().toString(36).substring(2, 10)}.${host}`;

    try {
      const lookupRes = await resilientLookup(randomSubdomain);
      if (lookupRes && lookupRes.address) {
        wildcardResolves = true;
        wildcardIp = lookupRes.address;
      }
    } catch {
      // Expected: non-existent subdomain should fail to resolve
    }

    if (wildcardResolves) {
      findings.push({
        category: 'DNS_HEALTH',
        findingCode: 'DNS-WILDCARD-ENABLED',
        title: 'Wildcard DNS Record Configured (*.' + host + ')',
        description: `Non-existent subdomains (e.g. ${randomSubdomain}) resolve to ${wildcardIp}. Overly broad wildcard DNS entries can mask dangling subdomain takeovers and expose unintended routing.`,
        severity: 'INFORMATIONAL',
        confidence: 'CONFIRMED',
        remediationGuidance: 'Review wildcard DNS records and prefer explicit FQDN mappings for designated services.',
      });
    }

    evidence.push({
      checkType: 'DNS_HEALTH',
      rawObservation: {
        host,
        caa: {
          present: caaRecords.length > 0,
          records: caaRecords,
        },
        nameservers: {
          configured: nameservers,
          dangling: danglingNs,
        },
        dnssec: {
          enabled: dnssecConfigured,
        },
        wildcard: {
          enabled: wildcardResolves,
          resolvedIp: wildcardIp,
        },
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
