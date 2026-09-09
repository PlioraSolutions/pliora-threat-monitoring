import { normalizeDiscoveredHostname, isValidHostname, upsertDiscoveredAsset } from './upsertAsset';
import { queryCertificateTransparency } from './ctLog';
import { enumerateDnsPermutations, DnsPermutationOptions } from './dnsPermutation';

export interface PassiveDiscoveryInput {
  organizationId: string;
  rootDomain: string;
  parentVerified?: boolean;
  skipCtLog?: boolean;
  skipDnsPermutation?: boolean;
  permutationWordlist?: string[];
  permutationConcurrency?: number;
}

export interface PassiveDiscoveryResult {
  rootDomain: string;
  totalDiscovered: number;
  newAssets: number;
  mergedAssets: number;
  unchangedAssets: number;
  assets: any[];
  sources: {
    ctLog: number;
    dnsPermutation: number;
  };
  errors: string[];
  durationMs: number;
}

/**
 * Unified Passive Asset Discovery Coordinator (Pillar 1 §1.1).
 * 
 * Orchestrates:
 * 1. Certificate Transparency (CT) log queries via crt.sh
 * 2. Active DNS prefix permutation enumeration
 * 3. Atomic asset upsert and multi-provenance deduplication
 * 4. Verification inheritance propagation (same-apex subdomains inherit verification)
 */
export async function runPassiveDiscovery(
  input: PassiveDiscoveryInput
): Promise<PassiveDiscoveryResult> {
  const start = Date.now();
  const normalizedRoot = normalizeDiscoveredHostname(input.rootDomain);

  if (!normalizedRoot || !isValidHostname(normalizedRoot)) {
    return {
      rootDomain: input.rootDomain,
      totalDiscovered: 0,
      newAssets: 0,
      mergedAssets: 0,
      unchangedAssets: 0,
      assets: [],
      sources: { ctLog: 0, dnsPermutation: 0 },
      errors: ['Invalid root domain specified for discovery.'],
      durationMs: Date.now() - start,
    };
  }

  const errors: string[] = [];
  const ctCandidates: string[] = [];
  const dnsCandidates: string[] = [];

  // Run discovery mechanisms concurrently
  const [ctSettled, dnsSettled] = await Promise.allSettled([
    !input.skipCtLog
      ? queryCertificateTransparency(normalizedRoot)
      : Promise.resolve<import('./ctLog').CtLogResult>({ candidates: [] }),
    !input.skipDnsPermutation
      ? enumerateDnsPermutations(normalizedRoot, {
          wordlist: input.permutationWordlist,
          concurrency: input.permutationConcurrency,
        })
      : Promise.resolve({ candidates: [], totalTested: 0, durationMs: 0 }),
  ]);

  if (ctSettled.status === 'fulfilled') {
    ctCandidates.push(...ctSettled.value.candidates);
    if (ctSettled.value.error) {
      errors.push(`CT_LOG: ${ctSettled.value.error}`);
    }
  } else {
    errors.push(`CT_LOG: ${ctSettled.reason?.message || 'Unknown CT error'}`);
  }

  if (dnsSettled.status === 'fulfilled') {
    dnsCandidates.push(...dnsSettled.value.candidates);
  } else {
    errors.push(`DNS_PERMUTATION: ${dnsSettled.reason?.message || 'Unknown DNS permutation error'}`);
  }

  // Deduplicate and upsert each candidate into canonical Asset store
  let newAssetsCount = 0;
  let mergedAssetsCount = 0;
  let unchangedAssetsCount = 0;
  const processedAssetsMap = new Map<string, any>();

  // 1. Process CT candidates
  for (const fqdn of ctCandidates) {
    const res = await upsertDiscoveredAsset({
      organizationId: input.organizationId,
      rootDomain: normalizedRoot,
      fqdn,
      method: 'CT_LOG',
      parentVerified: input.parentVerified,
    });

    if (res) {
      processedAssetsMap.set(fqdn, res.asset);
      if (res.action === 'CREATED') newAssetsCount++;
      else if (res.action === 'MERGED') mergedAssetsCount++;
      else unchangedAssetsCount++;
    }
  }

  // 2. Process DNS permutation candidates
  for (const fqdn of dnsCandidates) {
    const res = await upsertDiscoveredAsset({
      organizationId: input.organizationId,
      rootDomain: normalizedRoot,
      fqdn,
      method: 'DNS_PERMUTATION',
      parentVerified: input.parentVerified,
    });

    if (res) {
      // Overwrite or update with latest merged asset document
      processedAssetsMap.set(fqdn, res.asset);
      if (res.action === 'CREATED') newAssetsCount++;
      else if (res.action === 'MERGED') mergedAssetsCount++;
      else unchangedAssetsCount++;
    }
  }

  const allAssets = Array.from(processedAssetsMap.values());

  return {
    rootDomain: normalizedRoot,
    totalDiscovered: allAssets.length,
    newAssets: newAssetsCount,
    mergedAssets: mergedAssetsCount,
    unchangedAssets: unchangedAssetsCount,
    assets: allAssets,
    sources: {
      ctLog: ctCandidates.length,
      dnsPermutation: dnsCandidates.length,
    },
    errors,
    durationMs: Date.now() - start,
  };
}
