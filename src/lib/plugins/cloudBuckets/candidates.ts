/**
 * PLIŌRA Threat Monitor — Cloud Storage Bucket Candidate Generator
 * 
 * Generates permutation candidate bucket names for an organization/domain
 * across major cloud object store naming conventions (AWS S3, Google Cloud Storage, Azure Blob).
 * 
 * Invariants & Bounds:
 * - Maximum candidate bound: Tunable constant MAX_CANDIDATES_PER_DOMAIN (default: 100).
 * - S3/GCS naming rules: lowercase, numbers, hyphens, 3-63 chars, no leading/trailing hyphens.
 * - In-memory TTL cache (24 hours) per domain/org key to avoid recomputation on every tick.
 */

export const MAX_CANDIDATES_PER_DOMAIN = 100;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

interface CachedCandidates {
  candidates: string[];
  expiresAt: number;
}

const candidateCache = new Map<string, CachedCandidates>();

const COMMON_SUFFIXES = [
  '-backup',
  '-backups',
  '-assets',
  '-static',
  '-media',
  '-uploads',
  '-data',
  '-prod',
  '-production',
  '-dev',
  '-development',
  '-staging',
  '-stage',
  '-test',
  '-files',
  '-logs',
  '-public',
  '-private',
  '-internal',
  '-archive',
  '-docs',
  '-app',
  '-storage',
  '-cdn',
];

const COMMON_PREFIXES = [
  'backup-',
  'assets-',
  'static-',
  'data-',
  'public-',
  'media-',
  'files-',
  'logs-',
];

/**
 * Normalizes and validates a candidate bucket name against cloud provider rules.
 */
function sanitizeBucketName(name: string): string | null {
  const cleaned = name.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
  if (cleaned.length < 3 || cleaned.length > 63) {
    return null;
  }
  return cleaned;
}

/**
 * Generates bounded candidate bucket names for an asset domain and organization.
 */
export function generateBucketCandidates(
  domain: string,
  orgName?: string,
  bypassCache: boolean = false
): string[] {
  const normalizedDomain = domain.toLowerCase().trim();
  const cacheKey = `${normalizedDomain}::${(orgName || '').toLowerCase().trim()}`;

  if (!bypassCache) {
    const cached = candidateCache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.candidates;
    }
  }

  const baseRoots = new Set<string>();

  // 1. Extract base roots from domain
  const parts = normalizedDomain.split('.');
  if (parts.length >= 2) {
    const sld = parts[parts.length - 2]; // e.g., 'example' from 'example.com' or 'sub.example.com'
    const fullSld = parts[0];
    baseRoots.add(sld);
    baseRoots.add(fullSld);

    // Hyphenated and concatenated domain variations
    baseRoots.add(normalizedDomain.replace(/\./g, '-'));
    baseRoots.add(normalizedDomain.replace(/\./g, ''));
  } else {
    baseRoots.add(normalizedDomain);
  }

  // 2. Extract base roots from organization name
  if (orgName && orgName.trim()) {
    const orgSlug = orgName.toLowerCase().replace(/[^a-z0-9]/g, '');
    const orgHyphen = orgName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    if (orgSlug.length >= 3) baseRoots.add(orgSlug);
    if (orgHyphen.length >= 3) baseRoots.add(orgHyphen);
  }

  const candidatesSet = new Set<string>();

  for (const root of Array.from(baseRoots)) {
    const sanitizedRoot = sanitizeBucketName(root);
    if (!sanitizedRoot) continue;

    // Exact match
    candidatesSet.add(sanitizedRoot);

    // Suffix variants
    for (const suffix of COMMON_SUFFIXES) {
      const candidate = sanitizeBucketName(`${sanitizedRoot}${suffix}`);
      if (candidate) candidatesSet.add(candidate);
      if (candidatesSet.size >= MAX_CANDIDATES_PER_DOMAIN) break;
    }

    if (candidatesSet.size >= MAX_CANDIDATES_PER_DOMAIN) break;

    // Prefix variants
    for (const prefix of COMMON_PREFIXES) {
      const candidate = sanitizeBucketName(`${prefix}${sanitizedRoot}`);
      if (candidate) candidatesSet.add(candidate);
      if (candidatesSet.size >= MAX_CANDIDATES_PER_DOMAIN) break;
    }

    if (candidatesSet.size >= MAX_CANDIDATES_PER_DOMAIN) break;
  }

  const result = Array.from(candidatesSet).slice(0, MAX_CANDIDATES_PER_DOMAIN);

  candidateCache.set(cacheKey, {
    candidates: result,
    expiresAt: Date.now() + CACHE_TTL_MS,
  });

  return result;
}

/**
 * Clears the candidate cache (useful for testing).
 */
export function clearBucketCandidateCache(): void {
  candidateCache.clear();
}
