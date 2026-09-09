import { normalizeDiscoveredHostname, isValidHostname } from './upsertAsset';

export interface CtLogResult {
  candidates: string[];
  error?: string;
  cached?: boolean;
  timedOut?: boolean;
}

interface CtCacheEntry {
  candidates: string[];
  timestamp: number;
}

const ctCache = new Map<string, CtCacheEntry>();
export const CT_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

export function clearCtCache(): void {
  ctCache.clear();
}

/**
 * Queries public Certificate Transparency (CT) logs via crt.sh for subdomains of rootDomain.
 * 
 * Invariants:
 * - 8-second abort timeout prevents slow upstream responses from hanging scans.
 * - 5-minute in-memory cache avoids duplicate queries and respects crt.sh rate limits.
 * - Graceful degradation: Catches all network/parse errors and timeouts, never throws.
 * - Candidate normalization: Strips wildcard prefixes, normalizes to RFC 1123, filters same-apex names.
 */
export async function queryCertificateTransparency(
  rootDomain: string
): Promise<CtLogResult> {
  const normalizedRoot = normalizeDiscoveredHostname(rootDomain);
  if (!normalizedRoot || !isValidHostname(normalizedRoot)) {
    return { candidates: [], error: 'Invalid root domain' };
  }

  // Check in-memory cache
  const cached = ctCache.get(normalizedRoot);
  if (cached && Date.now() - cached.timestamp < CT_CACHE_TTL_MS) {
    return {
      candidates: cached.candidates,
      cached: true,
    };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort();
  }, 8000);

  const url = `https://crt.sh/?q=%.${encodeURIComponent(normalizedRoot)}&output=json`;

  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'PLIORA-ThreatMonitor-Discovery/1.0',
      },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!res.ok) {
      console.warn(`[CTLog] crt.sh query for ${normalizedRoot} returned HTTP ${res.status}`);
      return {
        candidates: [],
        error: `CT log provider returned HTTP ${res.status}`,
        timedOut: false,
      };
    }

    const text = await res.text();
    let entries: any[] = [];
    try {
      entries = JSON.parse(text);
    } catch {
      console.warn(`[CTLog] crt.sh returned non-JSON response for ${normalizedRoot}`);
      return {
        candidates: [],
        error: 'Invalid JSON response from CT provider',
        timedOut: false,
      };
    }

    if (!Array.isArray(entries)) {
      return { candidates: [] };
    }

    const discoveredSet = new Set<string>();

    for (const entry of entries) {
      const candidatesToTest: string[] = [];

      if (entry.common_name && typeof entry.common_name === 'string') {
        candidatesToTest.push(...entry.common_name.split(/[\r\n]+/));
      }

      if (entry.name_value && typeof entry.name_value === 'string') {
        candidatesToTest.push(...entry.name_value.split(/[\r\n]+/));
      }

      for (const rawName of candidatesToTest) {
        const normalized = normalizeDiscoveredHostname(rawName);
        if (
          normalized &&
          isValidHostname(normalized) &&
          (normalized === normalizedRoot || normalized.endsWith('.' + normalizedRoot))
        ) {
          discoveredSet.add(normalized);
        }
      }
    }

    const candidateList = Array.from(discoveredSet).sort();

    // Cache successful response
    ctCache.set(normalizedRoot, {
      candidates: candidateList,
      timestamp: Date.now(),
    });

    return {
      candidates: candidateList,
      cached: false,
    };
  } catch (err: any) {
    clearTimeout(timeoutId);
    const isTimeout = err.name === 'AbortError';
    console.warn(
      `[CTLog] Discovery failed for ${normalizedRoot}: ${isTimeout ? 'Request timed out after 8000ms' : err.message}`
    );

    return {
      candidates: [],
      error: isTimeout ? 'CT log query timed out after 8000ms' : err.message,
      timedOut: isTimeout,
    };
  }
}
