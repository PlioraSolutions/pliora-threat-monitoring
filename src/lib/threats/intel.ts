import dns from 'dns';
import net from 'net';

export interface DnsResolutionResult {
  isLive: boolean;
  ips: string[];
  hasMx: boolean;
  mxRecords?: string[];
  error?: string;
}

export interface DomainAgeResult {
  ageDays?: number;
  createdDate?: string;
  registrar?: string;
  error?: string;
}

export interface AsnLookupResult {
  asn?: string;
  org?: string;
  isKnownAbuseAsn: boolean;
}

// Known high-abuse bulletproof hosting ASNs, disposable bulletproof hosters, and known phishing staging networks
export const KNOWN_HIGH_ABUSE_ASNS = new Set<string>([
  'AS44477',  // Stark Industries Solutions
  'AS200019', // Alexhost SRL
  'AS202425', // IP Volume inc
  'AS212238', // Datacamp Limited
  'AS47583',  // Hostinger International (often misused for disposable phishing)
  'AS197695', // Reg.ru hosting
  'AS206804', // EstNOC OY
  'AS51852',  // Private Layer INC
  'AS43350',  // NForce Entertainment B.V.
]);

/**
 * Resolves A, AAAA, and MX records for a look-alike domain to check live readiness.
 */
export async function resolveDomainDns(
  domain: string,
  timeoutMs = 4000
): Promise<DnsResolutionResult> {
  const result: DnsResolutionResult = {
    isLive: false,
    ips: [],
    hasMx: false,
    mxRecords: [],
  };

  try {
    const resolver = dns.promises;

    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('DNS query timed out')), timeoutMs)
    );

    // Resolve A and AAAA in parallel
    const ipPromises = Promise.allSettled([
      Promise.race([resolver.resolve4(domain), timeoutPromise]),
      Promise.race([resolver.resolve6(domain), timeoutPromise]),
    ]);

    // Resolve MX in parallel
    const mxPromise = Promise.race([resolver.resolveMx(domain), timeoutPromise]).catch(() => []);

    const [ipResults, mxResults] = await Promise.all([ipPromises, mxPromise]);

    for (const res of ipResults) {
      if (res.status === 'fulfilled' && Array.isArray(res.value)) {
        result.ips.push(...res.value);
      }
    }

    if (result.ips.length > 0) {
      result.isLive = true;
    }

    if (Array.isArray(mxResults) && mxResults.length > 0) {
      result.hasMx = true;
      result.mxRecords = mxResults.map((m: any) => m.exchange || String(m));
    }
  } catch (err: any) {
    result.error = err?.message || 'DNS resolution failed';
  }

  return result;
}

/**
 * Looks up domain registration age via ICANN RDAP (Registration Data Access Protocol).
 * Computes age in days since initial registration.
 */
export async function lookupDomainAge(
  domain: string,
  timeoutMs = 5000
): Promise<DomainAgeResult> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const url = `https://rdap.org/domain/${encodeURIComponent(domain.toLowerCase().trim())}`;
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/rdap+json, application/json',
        'User-Agent': 'PLIORA-ThreatMonitor-RDAP/1.0',
      },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!res.ok) {
      return { error: `RDAP lookup returned HTTP ${res.status}` };
    }

    const data = await res.json();
    let createdDateStr: string | undefined;

    // RDAP events array contains registration/created events
    if (Array.isArray(data.events)) {
      for (const ev of data.events) {
        if (ev.eventAction === 'registration' || ev.eventAction === 'created') {
          createdDateStr = ev.eventDate;
          break;
        }
      }
    }

    // Fallback: check entities for registrar details
    let registrarName: string | undefined;
    if (Array.isArray(data.entities)) {
      for (const ent of data.entities) {
        if (Array.isArray(ent.roles) && ent.roles.includes('registrar')) {
          registrarName = ent.vcardArray?.[1]?.find((f: any) => f[0] === 'fn')?.[3] || ent.handle;
          break;
        }
      }
    }

    if (!createdDateStr) {
      return { registrar: registrarName };
    }

    const createdTime = new Date(createdDateStr).getTime();
    if (isNaN(createdTime)) {
      return { createdDate: createdDateStr, registrar: registrarName };
    }

    const ageDays = Math.max(0, Math.floor((Date.now() - createdTime) / (1000 * 60 * 60 * 24)));

    return {
      ageDays,
      createdDate: createdDateStr,
      registrar: registrarName,
    };
  } catch (err: any) {
    clearTimeout(timeoutId);
    return {
      error: err?.message || 'RDAP lookup failed',
    };
  }
}

/**
 * Looks up ASN information for an IP address using DNS Team Cymru IP-to-ASN mapping.
 * Reverse format: D.C.B.A.origin.asn.cymru.com
 */
export async function lookupIpAsn(
  ip: string,
  timeoutMs = 4000
): Promise<AsnLookupResult> {
  const result: AsnLookupResult = {
    isKnownAbuseAsn: false,
  };

  if (!net.isIPv4(ip)) {
    return result;
  }

  try {
    const reversedIp = ip.split('.').reverse().join('.');
    const queryHost = `${reversedIp}.origin.asn.cymru.com`;

    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('ASN lookup timed out')), timeoutMs)
    );

    const txtRecords = await Promise.race([
      dns.promises.resolveTxt(queryHost),
      timeoutPromise,
    ]);

    if (Array.isArray(txtRecords) && txtRecords.length > 0 && txtRecords[0].length > 0) {
      // Format: "15169 | 8.8.4.0/24 | US | arin | 1992-12-01"
      const line = txtRecords[0][0];
      const parts = line.split('|').map((s) => s.trim());
      if (parts.length >= 1) {
        const asnNumber = parts[0];
        result.asn = `AS${asnNumber}`;
        result.org = parts[1] || '';
        result.isKnownAbuseAsn = KNOWN_HIGH_ABUSE_ASNS.has(result.asn);
      }
    }
  } catch {
    // Graceful silent fallback
  }

  return result;
}
