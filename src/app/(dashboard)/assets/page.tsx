'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import {
  Globe,
  PlusCircle,
  RefreshCw,
  Search,
  Filter,
  Play,
  Compass,
  AlertCircle,
  CheckCircle2,
  Loader2,
  ExternalLink,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/client/api';
import { StatusBadge } from '@/components/StatusBadge';
import { ProvenanceBadge } from '@/components/ProvenanceBadge';

interface AssetItem {
  _id: string;
  id?: string;
  rootDomain: string;
  fqdn: string;
  type: string;
  importance: 'CRITICAL' | 'HIGH' | 'NORMAL' | 'LOW';
  verificationStatus: 'PENDING' | 'VERIFIED' | 'INHERITED_VERIFIED' | 'FAILED';
  verificationToken?: string;
  discoveredVia?: string[];
  ipAddresses?: string[];
  firstSeen?: string;
  lastSeen?: string;
  createdAt: string;
}

export default function AssetsPage() {
  const { role } = useAuth();
  const isViewer = role === 'VIEWER';

  const [assets, setAssets] = useState<AssetItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [actionAssetId, setActionAssetId] = useState<string | null>(null);
  const [actionFeedback, setActionFeedback] = useState<{ id: string; message: string; isError?: boolean } | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [provenanceFilter, setProvenanceFilter] = useState('ALL');
  const [typeFilter, setTypeFilter] = useState('ALL');

  const fetchAssets = useCallback(async () => {
    try {
      const res = await api.get('/api/assets');
      const list = Array.isArray(res) ? res : res?.data || [];
      setAssets(list);
    } catch (err) {
      console.error('Failed to load assets:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchAssets();
  }, [fetchAssets]);

  const handleImportanceChange = async (assetId: string, newImportance: string) => {
    if (isViewer) return;
    try {
      await api.patch(`/api/assets/${assetId}`, { importance: newImportance });
      setAssets((prev) =>
        prev.map((a) => (a._id === assetId || a.id === assetId ? { ...a, importance: newImportance as any } : a))
      );
    } catch (err: any) {
      alert(`Could not update asset importance: ${err.message}`);
    }
  };

  const handleTriggerDiscovery = async (asset: AssetItem) => {
    if (isViewer) return;
    const id = asset._id || asset.id!;
    setActionAssetId(id);
    setActionFeedback(null);
    try {
      const res = await api.post(`/api/assets/${id}/discover`);
      setActionFeedback({
        id,
        message: `Passive discovery completed: ${res?.newAssetsCount || 0} subdomains added.`,
      });
      await fetchAssets();
    } catch (err: any) {
      setActionFeedback({
        id,
        message: err.message || 'Discovery trigger failed.',
        isError: true,
      });
    } finally {
      setActionAssetId(null);
    }
  };

  const handleTriggerScan = async (asset: AssetItem) => {
    if (isViewer) return;
    const id = asset._id || asset.id!;
    setActionAssetId(id);
    setActionFeedback(null);
    try {
      await api.post('/api/scans', {
        assetId: id,
        scanType: 'FULL_SWEEP',
      });
      setActionFeedback({
        id,
        message: 'Scan queued successfully! Check status in Scan History.',
      });
    } catch (err: any) {
      setActionFeedback({
        id,
        message: err.message || 'Failed to queue scan.',
        isError: true,
      });
    } finally {
      setActionAssetId(null);
    }
  };

  const handleDeleteAsset = async (asset: AssetItem) => {
    if (isViewer) return;
    const id = asset._id || asset.id!;
    const isRoot =
      asset.type === 'ROOT_DOMAIN' ||
      !asset.fqdn.includes('.') ||
      asset.fqdn === asset.rootDomain;

    const confirmMsg = isRoot
      ? `Are you sure you want to delete root domain "${asset.fqdn}"? This will also remove all its discovered subdomains and associated scan findings.`
      : `Are you sure you want to delete asset "${asset.fqdn}" from inventory?`;

    if (!window.confirm(confirmMsg)) {
      return;
    }

    setActionAssetId(id);
    setActionFeedback(null);

    try {
      await api.delete(`/api/assets/${id}`);
      setActionFeedback({
        id,
        message: `Asset "${asset.fqdn}" was successfully deleted.`,
      });
      setAssets((prev) =>
        prev.filter((a) => {
          const aId = a._id || a.id;
          if (aId === id) return false;
          if (isRoot && a.rootDomain === asset.rootDomain) return false;
          return true;
        })
      );
    } catch (err: any) {
      setActionFeedback({
        id,
        message: err.message || 'Failed to delete asset.',
        isError: true,
      });
    } finally {
      setActionAssetId(null);
    }
  };

  // Filtered Assets
  const filteredAssets = assets.filter((a) => {
    const matchesSearch =
      !searchQuery ||
      a.fqdn.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.rootDomain.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.ipAddresses?.some((ip) => ip.includes(searchQuery));

    const matchesProvenance =
      provenanceFilter === 'ALL' ||
      (a.discoveredVia && a.discoveredVia.includes(provenanceFilter));

    const matchesType =
      typeFilter === 'ALL' || a.type === typeFilter;

    return matchesSearch && matchesProvenance && matchesType;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-text-primary">
            Asset Inventory
          </h1>
          <p className="text-caption text-text-secondary mt-0.5">
            Catalog of all verified domains and passively discovered external attack surface endpoints.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              setRefreshing(true);
              fetchAssets();
            }}
            disabled={refreshing}
            className="px-3.5 py-2 rounded-lg bg-surface border border-border hover:bg-surface-raised text-text-secondary hover:text-text-primary text-caption font-medium transition-colors flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          <Link
            href="/onboarding"
            className="px-4 py-2 rounded-lg bg-accent hover:bg-accent-hover text-white text-caption font-semibold transition-colors flex items-center gap-1.5 shadow-sm"
          >
            <PlusCircle className="w-4 h-4" />
            <span>Add Asset</span>
          </Link>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-surface border border-border rounded-xl p-4 flex flex-wrap items-center justify-between gap-4 shadow-sm">
        {/* Search */}
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-text-tertiary absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by domain, subdomain, or IP..."
            className="w-full pl-9 pr-4 py-2 bg-surface-raised border border-border rounded-lg text-body text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none transition-colors"
          />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Provenance Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-caption text-text-tertiary font-medium">Source:</span>
            <select
              value={provenanceFilter}
              onChange={(e) => setProvenanceFilter(e.target.value)}
              className="px-3 py-1.5 bg-surface-raised border border-border rounded-lg text-caption text-text-primary focus:border-accent focus:outline-none"
            >
              <option value="ALL">All Sources</option>
              <option value="MANUAL">Manual Entry</option>
              <option value="CT_LOG">CT Log Discovery</option>
              <option value="DNS_PERMUTATION">DNS Permutation</option>
            </select>
          </div>

          {/* Type Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-caption text-text-tertiary font-medium">Type:</span>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="px-3 py-1.5 bg-surface-raised border border-border rounded-lg text-caption text-text-primary focus:border-accent focus:outline-none"
            >
              <option value="ALL">All Types</option>
              <option value="DOMAIN">Apex Domain</option>
              <option value="SUBDOMAIN">Subdomain</option>
              <option value="IP">IP Address</option>
            </select>
          </div>
        </div>
      </div>

      {/* Action Feedback Banner */}
      {actionFeedback && (
        <div
          className={`p-3.5 rounded-lg border flex items-center justify-between text-caption ${
            actionFeedback.isError
              ? 'bg-sev-critical/10 border-sev-critical/30 text-sev-critical'
              : 'bg-sev-low/10 border-sev-low/30 text-sev-low'
          }`}
        >
          <span>{actionFeedback.message}</span>
          <button
            onClick={() => setActionFeedback(null)}
            className="text-text-tertiary hover:text-text-primary ml-2"
          >
            ✕
          </button>
        </div>
      )}

      {/* Assets Table */}
      {loading ? (
        <div className="py-16 flex flex-col items-center justify-center space-y-3">
          <Loader2 className="w-8 h-8 text-accent animate-spin" />
          <p className="text-caption text-text-secondary">Loading asset catalog...</p>
        </div>
      ) : filteredAssets.length === 0 ? (
        <div className="bg-surface border border-border rounded-xl p-12 text-center space-y-3">
          <Globe className="w-10 h-10 text-text-tertiary mx-auto" />
          <h3 className="text-body font-semibold text-text-primary">No assets match criteria</h3>
          <p className="text-caption text-text-secondary max-w-sm mx-auto">
            {assets.length === 0
              ? 'You have not added any domains to monitor yet.'
              : 'No assets matched your search and filter parameters.'}
          </p>
          {assets.length === 0 && (
            <Link
              href="/onboarding"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-accent text-white font-medium text-caption shadow mt-2"
            >
              <PlusCircle className="w-4 h-4" /> Add your first domain
            </Link>
          )}
        </div>
      ) : (
        <div className="bg-surface border border-border rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-body border-collapse">
              <thead>
                <tr className="bg-surface-raised border-b border-border text-caption font-semibold text-text-tertiary uppercase tracking-wider">
                  <th className="py-3.5 px-4">Asset / FQDN</th>
                  <th className="py-3.5 px-4">Verification</th>
                  <th className="py-3.5 px-4">Discovered Via</th>
                  <th className="py-3.5 px-4">Criticality</th>
                  <th className="py-3.5 px-4">IP Resolution</th>
                  <th className="py-3.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filteredAssets.map((asset) => {
                  const id = asset._id || asset.id!;
                  const isActionLoading = actionAssetId === id;
                  const isVerified =
                    asset.verificationStatus === 'VERIFIED' ||
                    asset.verificationStatus === 'INHERITED_VERIFIED';

                  return (
                    <tr key={id} className="hover:bg-surface-raised/50 transition-colors">
                      {/* Hostname */}
                      <td className="py-4 px-4">
                        <div className="space-y-0.5">
                          <div className="font-mono font-medium text-text-primary flex items-center gap-1.5">
                            <span>{asset.fqdn}</span>
                          </div>
                          {asset.type !== 'DOMAIN' && (
                            <div className="text-[11px] text-text-tertiary">
                              Root: {asset.rootDomain}
                            </div>
                          )}
                        </div>
                      </td>

                      {/* Verification Status */}
                      <td className="py-4 px-4">
                        <StatusBadge status={asset.verificationStatus} />
                      </td>

                      {/* Discovered Via Provenance Badges */}
                      <td className="py-4 px-4">
                        <div className="flex flex-wrap gap-1">
                          {asset.discoveredVia && asset.discoveredVia.length > 0 ? (
                            asset.discoveredVia.map((src) => (
                              <ProvenanceBadge key={src} method={src} />
                            ))
                          ) : (
                            <ProvenanceBadge method="MANUAL" />
                          )}
                        </div>
                      </td>

                      {/* Importance Dropdown */}
                      <td className="py-4 px-4">
                        {isViewer ? (
                          <span className="text-caption font-semibold text-text-secondary">
                            {asset.importance}
                          </span>
                        ) : (
                          <select
                            value={asset.importance}
                            onChange={(e) => handleImportanceChange(id, e.target.value)}
                            className="bg-surface-raised border border-border rounded px-2.5 py-1 text-caption font-medium text-text-primary focus:border-accent focus:outline-none"
                          >
                            <option value="CRITICAL">Critical</option>
                            <option value="HIGH">High</option>
                            <option value="NORMAL">Normal</option>
                            <option value="LOW">Low</option>
                          </select>
                        )}
                      </td>

                      {/* IP Addresses */}
                      <td className="py-4 px-4 font-mono text-caption text-text-secondary">
                        {asset.ipAddresses && asset.ipAddresses.length > 0 ? (
                          <span>{asset.ipAddresses.slice(0, 2).join(', ')}</span>
                        ) : (
                          <span className="text-text-tertiary italic">Pending scan</span>
                        )}
                      </td>

                      {/* Action Buttons */}
                      <td className="py-4 px-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          {!isVerified ? (
                            <Link
                              href={`/onboarding?id=${id}&domain=${encodeURIComponent(asset.rootDomain || asset.fqdn)}`}
                              className="px-3 py-1 rounded bg-sev-medium/10 text-sev-medium hover:bg-sev-medium/20 text-caption font-semibold border border-sev-medium/30 transition-colors"
                            >
                              Verify
                            </Link>
                          ) : (
                            <>
                              <button
                                disabled={isActionLoading || isViewer}
                                onClick={() => handleTriggerDiscovery(asset)}
                                title="Run passive subdomain discovery"
                                className="px-2.5 py-1 rounded bg-surface-raised hover:bg-surface-overlay text-text-secondary hover:text-text-primary text-caption font-medium border border-border transition-colors flex items-center gap-1 disabled:opacity-50"
                              >
                                <Compass className="w-3 h-3 text-accent" />
                                <span className="hidden sm:inline">Discovery</span>
                              </button>

                              <button
                                disabled={isActionLoading || isViewer}
                                onClick={() => handleTriggerScan(asset)}
                                title="Run full exposure scan sweep"
                                className="px-2.5 py-1 rounded bg-accent/15 hover:bg-accent/25 text-accent text-caption font-semibold border border-accent/30 transition-colors flex items-center gap-1 disabled:opacity-50"
                              >
                                {isActionLoading ? (
                                  <Loader2 className="w-3 h-3 animate-spin" />
                                ) : (
                                  <Play className="w-3 h-3" />
                                )}
                                <span>Scan</span>
                              </button>
                            </>
                          )}

                          {/* Delete Asset Button */}
                          <button
                            disabled={isActionLoading || isViewer}
                            onClick={() => handleDeleteAsset(asset)}
                            title={`Delete ${asset.fqdn} from asset inventory`}
                            className="p-1.5 rounded bg-sev-critical/10 hover:bg-sev-critical/20 text-sev-critical border border-sev-critical/20 hover:border-sev-critical/40 transition-colors flex items-center justify-center disabled:opacity-50"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
