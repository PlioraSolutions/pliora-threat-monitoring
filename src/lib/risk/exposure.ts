import { AssetType, VerificationStatus } from '@/types';

export interface AssetExposureInput {
  fqdn: string;
  type?: AssetType;
  verificationStatus?: VerificationStatus;
  ipAddresses?: string[];
  tags?: string[];
}

export interface ExposureBreakdown {
  assetTypeWeight: number;
  environmentWeight: number;
  reachabilityWeight: number;
  rawFactor: number;
  exposureFactor: number; // Clamped to [0.10, 1.00]
}

/**
 * Derives a normalized Exposure factor (0.10 to 1.00) for an asset.
 * 
 * Accounts for:
 * 1. Asset Type: Apex root domains have higher blast radius than isolated IPs or subdomains.
 * 2. Environment Heuristics: Identifies dev/staging/test hosts vs. high-profile prod/api/app hosts.
 * 3. Reachability: Verified hosts with resolved public IPs receive full exposure weight.
 */
export function deriveExposure(asset: AssetExposureInput): ExposureBreakdown {
  // 1. Asset Type Weight
  let assetTypeWeight = 0.85; // Default for subdomains
  switch (asset.type) {
    case 'ROOT_DOMAIN':
      assetTypeWeight = 1.0;
      break;
    case 'SUBDOMAIN':
      assetTypeWeight = 0.85;
      break;
    case 'SERVICE':
      assetTypeWeight = 0.75;
      break;
    case 'IP_ADDRESS':
      assetTypeWeight = 0.60;
      break;
    default:
      assetTypeWeight = 0.85;
  }

  // 2. Environment & Hostname Heuristic Weight
  const fqdnLower = (asset.fqdn || '').toLowerCase();
  const tags = (asset.tags || []).map((t) => t.toLowerCase());

  const nonProdRegex = /(^|\.)(staging|stage|dev|development|test|testing|qa|sandbox|demo|internal|corp|local|uat)\./i;
  const highValueProdRegex = /(^|\.)(prod|production|api|app|secure|auth|mail|portal|vpn|gateway|checkout|pay)\./i;

  let environmentWeight = 0.90; // Default standard exposure

  if (nonProdRegex.test(fqdnLower) || tags.some((t) => ['staging', 'dev', 'development', 'test', 'qa', 'sandbox'].includes(t))) {
    environmentWeight = 0.50; // Lower exposure for pre-prod / non-customer-facing hosts
  } else if (highValueProdRegex.test(fqdnLower) || tags.some((t) => ['production', 'prod', 'critical'].includes(t))) {
    environmentWeight = 1.00; // Maximum exposure for production critical endpoints
  }

  // 3. Reachability & Verification Weight
  let reachabilityWeight = 0.70; // Unverified or unresolved default
  const hasResolvedIps = Array.isArray(asset.ipAddresses) && asset.ipAddresses.length > 0;
  const isVerified =
    asset.verificationStatus === 'VERIFIED' ||
    asset.verificationStatus === 'INHERITED_VERIFIED';

  if (hasResolvedIps || isVerified) {
    reachabilityWeight = 1.00;
  }

  // Composite Exposure Calculation
  const rawFactor = assetTypeWeight * environmentWeight * reachabilityWeight;
  const exposureFactor = Math.min(1.0, Math.max(0.1, Number(rawFactor.toFixed(3))));

  return {
    assetTypeWeight,
    environmentWeight,
    reachabilityWeight,
    rawFactor,
    exposureFactor,
  };
}
