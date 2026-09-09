import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Asset, IAsset } from '@/models/Asset';
import { AuditLog } from '@/models/AuditLog';
import { generateVerificationToken } from '@/lib/verification';
import { DiscoveryMethod, AssetImportance, VerificationStatus } from '@/types';
import { triggerAlert } from '@/lib/alerts/service';

export interface UpsertDiscoveredAssetInput {
  organizationId: string;
  rootDomain: string;
  fqdn: string;
  method: DiscoveryMethod;
  parentVerified?: boolean;
  importance?: AssetImportance;
  tags?: string[];
}

export interface UpsertDiscoveredAssetResult {
  asset: any;
  isNew: boolean;
  action: 'CREATED' | 'MERGED' | 'UNCHANGED';
}

/**
 * Normalizes a hostname:
 * - Trims whitespace
 * - Converts to lowercase
 * - Strips leading wildcard (*.)
 * - Strips trailing dots
 */
export function normalizeDiscoveredHostname(hostname: string): string {
  if (!hostname || typeof hostname !== 'string') return '';
  return hostname
    .trim()
    .toLowerCase()
    .replace(/^\*\./, '')
    .replace(/\.+$/, '');
}

/**
 * Checks if a hostname is a valid syntax according to RFC 1123.
 */
export function isValidHostname(hostname: string): boolean {
  if (!hostname || hostname.length > 253) return false;
  const labels = hostname.split('.');
  if (labels.length < 2) return false;
  const labelRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
  return labels.every((label) => labelRegex.test(label));
}

/**
 * Canonical asset upsert function for all discovery mechanisms (§3.1 & §3.2).
 * 
 * Enforces:
 * 1. Single canonical Asset record per (organizationId, fqdn).
 * 2. Multi-provenance tracking in discoveredVia array (e.g. ['MANUAL', 'CT_LOG', 'DNS_PERMUTATION']).
 * 3. Verification Inheritance Rule (§1):
 *    - Discovered subdomains on the same apex domain inherit verification (INHERITED_VERIFIED) if parent is verified.
 *    - Discoveries on different domains remain PENDING until independently verified.
 * 4. Status preservation: Never downgrades an existing VERIFIED or INHERITED_VERIFIED asset.
 * 5. Earliest firstSeen preservation with lastSeen refreshed on every discovery.
 */
export async function upsertDiscoveredAsset(
  input: UpsertDiscoveredAssetInput
): Promise<UpsertDiscoveredAssetResult | null> {
  const normalizedFqdn = normalizeDiscoveredHostname(input.fqdn);
  const normalizedRoot = normalizeDiscoveredHostname(input.rootDomain);

  if (!isValidHostname(normalizedFqdn)) {
    return null;
  }

  const isSameApex =
    normalizedFqdn === normalizedRoot ||
    normalizedFqdn.endsWith('.' + normalizedRoot);

  const orgIdStr = input.organizationId.toString();

  // 1. Check if asset already exists for this tenant
  let existingAsset: any = null;

  if (isMongoActive()) {
    existingAsset = await Asset.findOne({
      organizationId: input.organizationId,
      fqdn: normalizedFqdn,
    });
  } else {
    const allAssets = Array.from(memoryStore.assets.values());
    existingAsset = allAssets.find(
      (a) =>
        a.organizationId?.toString() === orgIdStr &&
        a.fqdn === normalizedFqdn
    );
  }

  if (existingAsset) {
    // 2. Merge Behavior
    const currentMethods: DiscoveryMethod[] = Array.isArray(existingAsset.discoveredVia)
      ? existingAsset.discoveredVia
      : ['MANUAL'];

    const updatedMethods: DiscoveryMethod[] = Array.from(
      new Set([...currentMethods, input.method])
    );

    const hasNewMethod = updatedMethods.length > currentMethods.length;
    existingAsset.discoveredVia = updatedMethods;
    existingAsset.lastSeen = new Date();

    // Inheritance upgrade: If previously PENDING and parent root domain is verified on same apex
    if (
      existingAsset.verificationStatus === 'PENDING' &&
      input.parentVerified &&
      isSameApex
    ) {
      existingAsset.verificationStatus = 'INHERITED_VERIFIED';
      existingAsset.verifiedAt = existingAsset.verifiedAt || new Date();
    }

    if (isMongoActive()) {
      await existingAsset.save();
    } else {
      memoryStore.assets.set(existingAsset._id?.toString() || existingAsset.id, existingAsset);
    }

    return {
      asset: existingAsset,
      isNew: false,
      action: hasNewMethod ? 'MERGED' : 'UNCHANGED',
    };
  }

  // 3. Create New Discovered Asset Record
  const initialVerificationStatus: VerificationStatus =
    input.parentVerified && isSameApex ? 'INHERITED_VERIFIED' : 'PENDING';

  const verificationToken = generateVerificationToken();
  const assetType = normalizedFqdn === normalizedRoot ? 'ROOT_DOMAIN' : 'SUBDOMAIN';
  const defaultImportance: AssetImportance = input.importance || 'NORMAL';
  const defaultTags = input.tags || (isSameApex ? ['discovered', 'subdomain'] : ['discovered', 'external']);

  let newAsset: any = null;

  if (isMongoActive()) {
    newAsset = await Asset.create({
      organizationId: input.organizationId,
      rootDomain: normalizedRoot,
      fqdn: normalizedFqdn,
      type: assetType,
      importance: defaultImportance,
      verificationStatus: initialVerificationStatus,
      verificationToken,
      verifiedAt: initialVerificationStatus === 'INHERITED_VERIFIED' ? new Date() : undefined,
      discoveredVia: [input.method],
      ipAddresses: [],
      tags: defaultTags,
      firstSeen: new Date(),
      lastSeen: new Date(),
    });

    await AuditLog.create({
      organizationId: input.organizationId,
      actorId: 'system:discovery_engine',
      action: 'ASSET_DISCOVERED',
      objectType: 'Asset',
      objectId: newAsset._id.toString(),
      result: 'SUCCESS',
      details: {
        fqdn: normalizedFqdn,
        rootDomain: normalizedRoot,
        method: input.method,
        verificationStatus: initialVerificationStatus,
      },
    });
  } else {
    const assetId = `asset-disc-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    newAsset = {
      _id: assetId,
      organizationId: input.organizationId,
      rootDomain: normalizedRoot,
      fqdn: normalizedFqdn,
      type: assetType,
      importance: defaultImportance,
      verificationStatus: initialVerificationStatus,
      verificationToken,
      verifiedAt: initialVerificationStatus === 'INHERITED_VERIFIED' ? new Date() : undefined,
      discoveredVia: [input.method],
      ipAddresses: [],
      tags: defaultTags,
      firstSeen: new Date(),
      lastSeen: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    memoryStore.assets.set(assetId, newAsset);
    memoryStore.auditLogs.push({
      organizationId: input.organizationId,
      actorId: 'system:discovery_engine',
      action: 'ASSET_DISCOVERED',
      objectType: 'Asset',
      objectId: assetId,
      result: 'SUCCESS',
      details: {
        fqdn: normalizedFqdn,
        rootDomain: normalizedRoot,
        method: input.method,
        verificationStatus: initialVerificationStatus,
      },
      createdAt: new Date(),
    });
  }

  // Trigger alert for passive discoveries (CT_LOG, DNS_PERMUTATION) (§2.1)
  if (input.method !== 'MANUAL') {
    triggerAlert({
      organizationId: input.organizationId.toString(),
      type: 'NEW_ASSET_DISCOVERED',
      targetName: normalizedFqdn,
      asset: newAsset,
      method: input.method,
    }).catch(() => {});
  }

  return {
    asset: newAsset,
    isNew: true,
    action: 'CREATED',
  };
}
