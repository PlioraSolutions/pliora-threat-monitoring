/**
 * PLIŌRA Threat Monitor — Domain Permutation Generator
 * 
 * Generates look-alike, typosquatted, and impersonating domain candidates for a
 * customer's verified root domain across standard adversarial transformation classes.
 * 
 * Invariants & Bounds:
 * - Maximum candidate bound: Tunable constant MAX_PERMUTATIONS_PER_DOMAIN (default: 250).
 * - Maximum edit distance: <= 2 to prevent combinatorial explosion and unmanageable volume.
 * - In-memory LRU/TTL cache per domain to avoid recomputation on every tick.
 */

export interface PermutationCandidate {
  domain: string;
  fuzzer: 'omission' | 'repetition' | 'transposition' | 'replacement' | 'homoglyph' | 'keyword' | 'tld_variant';
  editDistance: number;
}

export interface PermutationOptions {
  maxCandidates?: number;
  includeTldVariants?: boolean;
  includeKeywords?: boolean;
}

export const MAX_PERMUTATIONS_PER_DOMAIN = 250;

// Common QWERTY keyboard adjacency mapping
const QWERTY_ADJACENCY: Record<string, string[]> = {
  a: ['q', 'w', 's', 'z'],
  b: ['v', 'g', 'h', 'n'],
  c: ['x', 'd', 'f', 'v'],
  d: ['s', 'e', 'r', 'f', 'c', 'x'],
  e: ['w', 's', 'd', 'r'],
  f: ['d', 'r', 't', 'g', 'v', 'c'],
  g: ['f', 't', 'y', 'h', 'b', 'v'],
  h: ['g', 'y', 'u', 'j', 'n', 'b'],
  i: ['u', 'j', 'k', 'o'],
  j: ['h', 'u', 'i', 'k', 'm', 'n'],
  k: ['j', 'i', 'o', 'l', 'm'],
  l: ['k', 'o', 'p'],
  m: ['n', 'j', 'k'],
  n: ['b', 'h', 'j', 'm'],
  o: ['i', 'k', 'l', 'p'],
  p: ['o', 'l'],
  q: ['w', 'a', 's'],
  r: ['e', 'd', 'f', 't'],
  s: ['a', 'w', 'e', 'd', 'x', 'z'],
  t: ['r', 'f', 'g', 'y'],
  u: ['y', 'h', 'j', 'i'],
  v: ['c', 'f', 'g', 'b'],
  w: ['q', 'a', 's', 'e'],
  x: ['z', 's', 'd', 'c'],
  y: ['t', 'g', 'h', 'u'],
  z: ['a', 's', 'x'],
  '0': ['9', 'o', 'p'],
  '1': ['2', 'q', 'l', 'i'],
  '2': ['1', '3', 'q', 'w'],
  '3': ['2', '4', 'w', 'e'],
  '4': ['3', '5', 'e', 'r'],
  '5': ['4', '6', 'r', 't'],
  '6': ['5', '7', 't', 'y'],
  '7': ['6', '8', 'y', 'u'],
  '8': ['7', '9', 'u', 'i'],
  '9': ['8', '0', 'i', 'o'],
};

// Common visual homoglyphs and character confusion mapping
const HOMOGLYPHS: Record<string, string[]> = {
  m: ['rn', 'nn'],
  w: ['vv'],
  o: ['0'],
  '0': ['o'],
  l: ['1', 'i'],
  '1': ['l', 'i'],
  i: ['l', '1'],
  c: ['k'],
  k: ['c'],
  v: ['u'],
  u: ['v'],
  d: ['cl'],
};

// Common targeted high-risk brand impersonation keywords
const PHISHING_KEYWORDS = [
  'login',
  'signin',
  'auth',
  'secure',
  'verify',
  'portal',
  'support',
  'account',
  'update',
  'app',
];

// Common alternate TLDs for brand squatted domains
const COMMON_TLD_VARIANTS = [
  'net',
  'org',
  'co',
  'info',
  'io',
  'app',
  'online',
  'tech',
  'xyz',
  'biz',
  'cc',
  'site',
];

// In-memory permutation cache with 15-minute TTL
const permutationCache = new Map<string, { candidates: PermutationCandidate[]; timestamp: number }>();
const CACHE_TTL_MS = 15 * 60 * 1000;

export function clearPermutationCache(): void {
  permutationCache.clear();
}

/**
 * Splits a domain into its second-level brand/name part and its top-level domain.
 * e.g., "acme.com" -> { name: "acme", tld: "com" }
 * e.g., "portal.acme.co.uk" -> { name: "portal.acme", tld: "co.uk" }
 */
export function parseDomainParts(rootDomain: string): { name: string; tld: string } {
  const parts = rootDomain.toLowerCase().trim().split('.');
  if (parts.length <= 1) {
    return { name: rootDomain.toLowerCase().trim(), tld: 'com' };
  }

  // Handle common two-part ccTLDs (e.g. .co.uk, .com.au, .org.uk)
  if (
    parts.length >= 3 &&
    ['co', 'com', 'org', 'net', 'gov', 'edu'].includes(parts[parts.length - 2]) &&
    parts[parts.length - 1].length === 2
  ) {
    const tld = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
    const name = parts.slice(0, -2).join('.');
    return { name, tld };
  }

  const tld = parts[parts.length - 1];
  const name = parts.slice(0, -1).join('.');
  return { name, tld };
}

/**
 * Generates typosquat and look-alike candidate domains for a target domain.
 */
export function generateDomainPermutations(
  rootDomain: string,
  options: PermutationOptions = {}
): PermutationCandidate[] {
  const normalized = rootDomain.toLowerCase().trim();
  const maxCandidates = options.maxCandidates ?? MAX_PERMUTATIONS_PER_DOMAIN;

  // Check cache
  const cached = permutationCache.get(normalized);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    return cached.candidates;
  }

  const { name, tld } = parseDomainParts(normalized);
  if (!name || name.length < 2) {
    return [];
  }

  const candidateMap = new Map<string, PermutationCandidate>();

  const addCandidate = (
    candidateDomain: string,
    fuzzer: PermutationCandidate['fuzzer'],
    editDistance: number
  ) => {
    if (candidateMap.size >= maxCandidates) return;
    if (candidateDomain === normalized) return; // Skip original
    if (!candidateMap.has(candidateDomain)) {
      candidateMap.set(candidateDomain, {
        domain: candidateDomain,
        fuzzer,
        editDistance,
      });
    }
  };

  // 1. Character Omission (acme -> ame, cme, ace, acm)
  for (let i = 0; i < name.length; i++) {
    const omitted = name.slice(0, i) + name.slice(i + 1);
    if (omitted.length >= 2) {
      addCandidate(`${omitted}.${tld}`, 'omission', 1);
    }
  }

  // 2. Character Repetition (acme -> aacme, accme, acmme, acmee)
  for (let i = 0; i < name.length; i++) {
    const repeated = name.slice(0, i + 1) + name[i] + name.slice(i + 1);
    addCandidate(`${repeated}.${tld}`, 'repetition', 1);
  }

  // 3. Adjacent Transposition (acme -> amce, ca-me)
  for (let i = 0; i < name.length - 1; i++) {
    const chars = name.split('');
    const temp = chars[i];
    chars[i] = chars[i + 1];
    chars[i + 1] = temp;
    addCandidate(`${chars.join('')}.${tld}`, 'transposition', 1);
  }

  // 4. QWERTY Key Replacement (acme -> scme, axme, etc.)
  for (let i = 0; i < name.length; i++) {
    const ch = name[i];
    const neighbors = QWERTY_ADJACENCY[ch] || [];
    for (const neighbor of neighbors) {
      const swapped = name.slice(0, i) + neighbor + name.slice(i + 1);
      addCandidate(`${swapped}.${tld}`, 'replacement', 1);
      if (candidateMap.size >= maxCandidates) break;
    }
    if (candidateMap.size >= maxCandidates) break;
  }

  // 5. Homoglyphs and Visual Confusables (m -> rn, o -> 0, l -> 1)
  for (let i = 0; i < name.length; i++) {
    const ch = name[i];
    const substitutes = HOMOGLYPHS[ch] || [];
    for (const sub of substitutes) {
      const glyph = name.slice(0, i) + sub + name.slice(i + 1);
      addCandidate(`${glyph}.${tld}`, 'homoglyph', sub.length);
      if (candidateMap.size >= maxCandidates) break;
    }
    if (candidateMap.size >= maxCandidates) break;
  }

  // 6. Phishing / Security Keyword Insertion
  if (options.includeKeywords !== false && candidateMap.size < maxCandidates) {
    for (const kw of PHISHING_KEYWORDS) {
      addCandidate(`${name}-${kw}.${tld}`, 'keyword', 2);
      addCandidate(`${kw}-${name}.${tld}`, 'keyword', 2);
      addCandidate(`${name}${kw}.${tld}`, 'keyword', 2);
      if (candidateMap.size >= maxCandidates) break;
    }
  }

  // 7. Common TLD Variants (acme.net, acme.org, acme.co, etc.)
  if (options.includeTldVariants !== false && candidateMap.size < maxCandidates) {
    for (const variantTld of COMMON_TLD_VARIANTS) {
      if (variantTld !== tld) {
        addCandidate(`${name}.${variantTld}`, 'tld_variant', 1);
        if (candidateMap.size >= maxCandidates) break;
      }
    }
  }

  const results = Array.from(candidateMap.values());
  permutationCache.set(normalized, { candidates: results, timestamp: Date.now() });
  return results;
}
