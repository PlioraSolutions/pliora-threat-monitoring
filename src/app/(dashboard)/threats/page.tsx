'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Layers,
  Search,
  RefreshCw,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  Play,
  Globe,
  Mail,
  Server,
  Clock,
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/client/api';
import { SeverityBadge } from '@/components/SeverityBadge';
import { StatusBadge } from '@/components/StatusBadge';
import { ThreatDrawer, ThreatDetailItem } from '@/components/ThreatDrawer';

export default function ThreatsPage() {
  const { role } = useAuth();
  const isViewer = role === 'VIEWER';

  const [threats, setThreats] = useState<ThreatDetailItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);

  // Detail drawer
  const [selectedThreat, setSelectedThreat] = useState<ThreatDetailItem | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const fetchThreats = useCallback(async () => {
    try {
      const res = await api.get('/api/threats');
      const list = res?.data || (Array.isArray(res) ? res : []);
      setThreats(list);
    } catch (err) {
      console.error('Failed to load threats:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchThreats();
  }, [fetchThreats]);

  const handleTriggerThreatScan = async () => {
    if (isViewer) return;
    setScanning(true);
    setScanMessage(null);
    try {
      const res = await api.post('/api/threats/scan');
      setScanMessage(`Threat monitoring sweep completed: ${res?.analyzedCandidates || 0} permutations checked.`);
      await fetchThreats();
    } catch (err: any) {
      setScanMessage(`Threat scan error: ${err.message}`);
    } finally {
      setScanning(false);
    }
  };

  const handleRowClick = (t: ThreatDetailItem) => {
    setSelectedThreat(t);
    setDrawerOpen(true);
  };

  const handleStatusChange = async (newStatus: 'MONITORING' | 'ACCEPTED_RISK' | 'RESOLVED') => {
    if (!selectedThreat || isViewer) return;
    try {
      await api.patch(`/api/threats/${selectedThreat.id}`, { status: newStatus });
      setDrawerOpen(false);
      setSelectedThreat(null);
      await fetchThreats();
    } catch (err: any) {
      alert(`Could not update threat: ${err.message}`);
    }
  };

  const filteredThreats = threats.filter((t) => {
    const matchesSearch =
      !searchQuery ||
      t.indicator.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (t.mutationType && t.mutationType.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesStatus = statusFilter === 'ALL' || t.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-text-primary">
            Threat & Brand Monitoring
          </h1>
          <p className="text-caption text-text-secondary mt-0.5">
            Active intelligence tracking typosquatted domains, look-alikes, and credential-phishing candidates.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              setRefreshing(true);
              fetchThreats();
            }}
            disabled={refreshing}
            className="px-3.5 py-2 rounded-lg bg-surface border border-border hover:bg-surface-raised text-text-secondary hover:text-text-primary text-caption font-medium transition-colors flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          <button
            onClick={handleTriggerThreatScan}
            disabled={scanning || isViewer}
            className="px-4 py-2 rounded-lg bg-accent hover:bg-accent-hover text-white text-caption font-semibold transition-colors flex items-center gap-1.5 shadow-sm disabled:opacity-50"
          >
            {scanning ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4" />
            )}
            <span>{scanning ? 'Running Sweep...' : 'Run Threat Sweep'}</span>
          </button>
        </div>
      </div>

      {/* Sweep Feedback Banner */}
      {scanMessage && (
        <div className="p-3.5 bg-accent/10 border border-accent/30 rounded-lg flex items-center justify-between text-caption text-text-primary">
          <span>{scanMessage}</span>
          <button onClick={() => setScanMessage(null)} className="text-text-tertiary hover:text-text-primary">
            ✕
          </button>
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="bg-surface border border-border rounded-xl p-4 flex flex-wrap items-center justify-between gap-4 shadow-sm">
        {/* Search */}
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-text-tertiary absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search indicator or technique..."
            className="w-full pl-9 pr-4 py-2 bg-surface-raised border border-border rounded-lg text-body text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none transition-colors"
          />
        </div>

        {/* Status Filter */}
        <div className="flex items-center gap-1.5">
          <span className="text-caption text-text-tertiary font-medium">Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 bg-surface-raised border border-border rounded-lg text-caption text-text-primary focus:border-accent focus:outline-none"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open Threats</option>
            <option value="MONITORING">Monitoring</option>
            <option value="ACCEPTED_RISK">Risk Accepted</option>
            <option value="RESOLVED">Resolved</option>
          </select>
        </div>
      </div>

      {/* Threats Table */}
      {loading ? (
        <div className="py-16 flex flex-col items-center justify-center space-y-3">
          <Loader2 className="w-8 h-8 text-accent animate-spin" />
          <p className="text-caption text-text-secondary">Loading threat indicators...</p>
        </div>
      ) : filteredThreats.length === 0 ? (
        <div className="bg-surface border border-border rounded-xl p-12 text-center space-y-3">
          <CheckCircle2 className="w-10 h-10 text-sev-low mx-auto" />
          <h3 className="text-body font-semibold text-text-primary">No active brand threats detected</h3>
          <p className="text-caption text-text-secondary max-w-sm mx-auto">
            Our typosquatting and CT-log permutations did not find high-risk look-alike domains for your brand.
          </p>
        </div>
      ) : (
        <div className="bg-surface border border-border rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-body border-collapse">
              <thead>
                <tr className="bg-surface-raised border-b border-border text-caption font-semibold text-text-tertiary uppercase tracking-wider">
                  <th className="py-3.5 px-4">Threat Indicator</th>
                  <th className="py-3.5 px-4">Technique</th>
                  <th className="py-3.5 px-4">Corroboration</th>
                  <th className="py-3.5 px-4">Active Signals</th>
                  <th className="py-3.5 px-4">Severity</th>
                  <th className="py-3.5 px-4">Status</th>
                  <th className="py-3.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filteredThreats.map((threat) => {
                  const factors = threat.corroborationFactors || {};

                  return (
                    <tr
                      key={threat.id}
                      onClick={() => handleRowClick(threat)}
                      className="hover:bg-surface-raised/60 transition-colors cursor-pointer"
                    >
                      {/* Indicator */}
                      <td className="py-4 px-4 font-mono font-bold text-text-primary">
                        {threat.indicator}
                      </td>

                      {/* Technique */}
                      <td className="py-4 px-4 text-caption text-text-secondary">
                        <span className="bg-surface-raised px-2 py-0.5 rounded border border-border">
                          {threat.mutationType || 'Permutation'}
                        </span>
                      </td>

                      {/* Corroboration Score */}
                      <td className="py-4 px-4">
                        <div className="font-bold text-text-primary">
                          {threat.corroborationScore}{' '}
                          <span className="text-[11px] font-normal text-text-tertiary">/ 100</span>
                        </div>
                      </td>

                      {/* Signals */}
                      <td className="py-4 px-4">
                        <div className="flex items-center gap-2 text-caption">
                          {factors.hasDnsA && (
                            <span className="inline-flex items-center gap-1 text-sev-high text-[11px] font-medium bg-sev-high/10 px-1.5 py-0.5 rounded border border-sev-high/20">
                              <Globe className="w-3 h-3" /> Resolving
                            </span>
                          )}
                          {factors.hasMx && (
                            <span className="inline-flex items-center gap-1 text-sev-critical text-[11px] font-medium bg-sev-critical/10 px-1.5 py-0.5 rounded border border-sev-critical/20">
                              <Mail className="w-3 h-3" /> MX Active
                            </span>
                          )}
                          {!factors.hasDnsA && !factors.hasMx && (
                            <span className="text-text-tertiary text-caption italic">
                              Dormant
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Severity */}
                      <td className="py-4 px-4 whitespace-nowrap">
                        <SeverityBadge severity={threat.severity} />
                      </td>

                      {/* Status */}
                      <td className="py-4 px-4 whitespace-nowrap">
                        <StatusBadge status={threat.status} />
                      </td>

                      {/* Actions */}
                      <td className="py-4 px-4 text-right whitespace-nowrap">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleRowClick(threat);
                          }}
                          className="px-3 py-1 rounded bg-surface-raised hover:bg-surface-overlay text-caption font-semibold text-text-primary border border-border transition-colors"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Threat Detail Drawer */}
      <ThreatDrawer
        threat={selectedThreat}
        isOpen={drawerOpen}
        onClose={() => {
          setDrawerOpen(false);
          setSelectedThreat(null);
        }}
        onStatusChange={handleStatusChange}
        userRole={role || 'MEMBER'}
      />
    </div>
  );
}
