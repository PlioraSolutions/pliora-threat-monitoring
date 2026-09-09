import dns from 'dns/promises';
import { normalizeDiscoveredHostname, isValidHostname } from './upsertAsset';

export const DEFAULT_SUBDOMAIN_WORDLIST: string[] = [
  'www',
  'api',
  'app',
  'dev',
  'staging',
  'mail',
  'vpn',
  'admin',
  'portal',
  'test',
  'stage',
  'auth',
  'login',
  'shop',
  'blog',
  'status',
  'docs',
  'cdn',
  'beta',
  'demo',
  'gateway',
  'secure',
  'dashboard',
  'monitor',
];

export interface DnsPermutationOptions {
  wordlist?: string[];
  concurrency?: number;
  timeoutMs?: number;
}

export interface DnsPermutationResult {
  candidates: string[];
  totalTested: number;
  durationMs: number;
}

/**
 * Checks if a specific hostname resolves via DNS lookup.
 */
async function resolvesHost(hostname: string): Promise<boolean> {
  try {
    const res = await dns.lookup(hostname);
    return Boolean(res && res.address);
  } catch {
    return false;
  }
}

/**
 * Executes throttled DNS permutation lookups against a root domain.
 * 
 * Invariants:
 * - Wordlist curated for high-value targets (admin, vpn, api, staging).
 * - Throttled concurrency (default 6) prevents DNS resolver exhaustion / rate limits.
 * - Non-blocking error handling: Any individual DNS lookup failure is ignored.
 */
export async function enumerateDnsPermutations(
  rootDomain: string,
  options: DnsPermutationOptions = {}
): Promise<DnsPermutationResult> {
  const start = Date.now();
  const normalizedRoot = normalizeDiscoveredHostname(rootDomain);

  if (!normalizedRoot || !isValidHostname(normalizedRoot)) {
    return { candidates: [], totalTested: 0, durationMs: Date.now() - start };
  }

  const wordlist = options.wordlist || DEFAULT_SUBDOMAIN_WORDLIST;
  const concurrency = Math.max(1, options.concurrency || 6);

  const discovered: string[] = [];
  const candidates = wordlist.map((prefix) => `${prefix}.${normalizedRoot}`);

  // Process in chunks according to concurrency limit
  for (let i = 0; i < candidates.length; i += concurrency) {
    const chunk = candidates.slice(i, i + concurrency);
    const chunkPromises = chunk.map(async (candidate) => {
      const exists = await resolvesHost(candidate);
      if (exists) {
        discovered.push(candidate);
      }
    });

    await Promise.all(chunkPromises);
  }

  return {
    candidates: discovered.sort(),
    totalTested: candidates.length,
    durationMs: Date.now() - start,
  };
}
