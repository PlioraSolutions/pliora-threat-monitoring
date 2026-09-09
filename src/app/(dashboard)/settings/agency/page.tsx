'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import {
  Shield,
  Users,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Loader2,
  Lock,
  Eye,
  Clock,
  Trash2,
  Sparkles,
  ArrowLeft,
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';

interface AgencyLinkItem {
  linkId: string;
  agencyOrgId: string;
  agencyName: string;
  agencySlug: string;
  status: 'PENDING' | 'ACTIVE' | 'REVOKED';
  scopes: string[];
  delegateBranding: boolean;
  grantedAt?: string;
  revokedAt?: string;
  createdAt: string;
}

interface AccessLogItem {
  id: string;
  actor: string;
  timestamp: string;
  agencyName: string;
  path: string;
  scopes: string[];
}

export default function ClientAgencySettingsPage() {
  const { role } = useAuth();
  const canManage = role === 'OWNER' || role === 'ADMIN';

  const [links, setLinks] = useState<AgencyLinkItem[]>([]);
  const [accessLogs, setAccessLogs] = useState<AccessLogItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const fetchAgencyData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetch('/api/org/agency-links');
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error?.message || 'Failed to load agency access settings');
      }

      setLinks(data.data?.links || []);
      setAccessLogs(data.data?.accessLogs || []);
    } catch (err: any) {
      setError(err.message || 'Error loading partner agencies');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAgencyData();
  }, [fetchAgencyData]);

  const handleAcceptLink = async (linkId: string) => {
    try {
      setActionLoading(`accept_${linkId}`);
      const res = await fetch(`/api/org/agency-links/${linkId}/accept`, {
        method: 'POST',
      });
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error?.message || 'Failed to accept agency link');
      }

      fetchAgencyData();
    } catch (err: any) {
      alert(err.message || 'Error accepting link');
    } finally {
      setActionLoading(null);
    }
  };

  const handleRevokeLink = async (linkId: string, agencyName: string) => {
    if (!confirm(`Are you sure you want to revoke access for "${agencyName}"? Access will be terminated immediately.`)) {
      return;
    }

    try {
      setActionLoading(`revoke_${linkId}`);
      const res = await fetch(`/api/org/agency-links/${linkId}/revoke`, {
        method: 'POST',
      });
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error?.message || 'Failed to revoke agency link');
      }

      fetchAgencyData();
    } catch (err: any) {
      alert(err.message || 'Error revoking link');
    } finally {
      setActionLoading(null);
    }
  };

  const handleToggleBranding = async (linkId: string, currentVal: boolean) => {
    try {
      setActionLoading(`branding_${linkId}`);
      const res = await fetch(`/api/org/agency-links/${linkId}/branding`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ delegateBranding: !currentVal }),
      });
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error?.message || 'Failed to update branding delegation');
      }

      setLinks((prev) =>
        prev.map((l) => (l.linkId === linkId ? { ...l, delegateBranding: !currentVal } : l))
      );
    } catch (err: any) {
      alert(err.message || 'Error updating branding');
    } finally {
      setActionLoading(null);
    }
  };

  const pendingLinks = links.filter((l) => l.status === 'PENDING');
  const activeLinks = links.filter((l) => l.status === 'ACTIVE');

  return (
    <div className="space-y-8 max-w-5xl mx-auto pb-12">
      {/* Header */}
      <div className="border-b border-border pb-6 flex items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Link href="/settings" className="text-xs text-text-tertiary hover:text-text-primary flex items-center gap-1">
              <ArrowLeft className="w-3 h-3" />
              <span>Back to Settings</span>
            </Link>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-text-primary flex items-center gap-3">
            <Shield className="w-6 h-6 text-accent" />
            <span>Partner Agency Access & Governance</span>
          </h1>
          <p className="text-body text-text-secondary text-sm mt-1">
            Authorize cybersecurity MSPs and agencies to monitor your organization's attack surface with strict read-only scopes.
          </p>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-sev-critical/10 border border-sev-critical/30 text-sev-critical text-sm">
          {error}
        </div>
      )}

      {loading ? (
        <div className="py-20 flex flex-col items-center justify-center text-text-secondary">
          <Loader2 className="w-8 h-8 animate-spin text-accent mb-3" />
          <p className="text-sm">Loading partner agency access settings...</p>
        </div>
      ) : (
        <>
          {/* Section 1: Pending Approval Requests */}
          {pendingLinks.length > 0 && (
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-sev-high animate-ping" />
                <h2 className="text-lg font-bold text-text-primary">
                  Pending Partner Access Requests ({pendingLinks.length})
                </h2>
              </div>

              <div className="space-y-3">
                {pendingLinks.map((link) => (
                  <div
                    key={link.linkId}
                    className="p-5 rounded-xl bg-surface border-2 border-accent/40 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-sm"
                  >
                    <div>
                      <div className="flex items-center gap-2.5">
                        <span className="font-semibold text-base text-text-primary">{link.agencyName}</span>
                        <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-sev-high/10 text-sev-high border border-sev-high/20 font-bold">
                          Pending Approval
                        </span>
                      </div>
                      <p className="text-xs text-text-secondary mt-1">
                        Requested: <span className="font-medium text-text-primary">Read-Only Scoped Access</span> (Findings, Assets, Brand Threats, Risk Score).
                      </p>
                      <p className="text-[11px] text-text-tertiary mt-1">
                        Invited on {new Date(link.createdAt).toLocaleDateString()} • No mutation or triage rights granted.
                      </p>
                    </div>

                    {canManage ? (
                      <div className="flex items-center gap-2 self-start sm:self-auto">
                        <button
                          onClick={() => handleAcceptLink(link.linkId)}
                          disabled={actionLoading === `accept_${link.linkId}`}
                          className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-accent hover:bg-accent-hover text-white text-xs font-semibold transition-colors shadow-sm disabled:opacity-50"
                        >
                          {actionLoading === `accept_${link.linkId}` ? (
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          ) : (
                            <CheckCircle2 className="w-3.5 h-3.5" />
                          )}
                          <span>Approve Access</span>
                        </button>

                        <button
                          onClick={() => handleRevokeLink(link.linkId, link.agencyName)}
                          disabled={actionLoading === `revoke_${link.linkId}`}
                          className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-surface-raised hover:bg-surface-overlay text-text-secondary hover:text-sev-critical text-xs font-medium border border-border transition-colors disabled:opacity-50"
                        >
                          <XCircle className="w-3.5 h-3.5" />
                          <span>Decline</span>
                        </button>
                      </div>
                    ) : (
                      <span className="text-xs text-text-tertiary italic">Approval requires Owner or Admin role</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Section 2: Active Authorized Agencies */}
          <div className="space-y-4">
            <h2 className="text-lg font-bold text-text-primary">
              Active Authorized Agencies ({activeLinks.length})
            </h2>

            {activeLinks.length === 0 ? (
              <div className="p-8 rounded-xl bg-surface border border-border text-center space-y-2">
                <Users className="w-8 h-8 text-text-tertiary mx-auto mb-1" />
                <p className="text-sm font-semibold text-text-primary">No External Agencies Linked</p>
                <p className="text-xs text-text-secondary max-w-md mx-auto">
                  When you approve an agency or MSP invitation, their authorized security analysts will appear here with audited read-only access.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {activeLinks.map((link) => (
                  <div
                    key={link.linkId}
                    className="p-5 rounded-xl bg-surface border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-sm"
                  >
                    <div className="space-y-2">
                      <div className="flex items-center gap-2.5">
                        <span className="font-semibold text-base text-text-primary">{link.agencyName}</span>
                        <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-sev-low/10 text-sev-low border border-sev-low/20 font-bold">
                          Active Link
                        </span>
                        <span className="text-xs px-2 py-0.5 rounded bg-surface-overlay text-text-tertiary border border-border font-mono">
                          Read-Only
                        </span>
                      </div>

                      <div className="text-xs text-text-secondary flex flex-wrap items-center gap-x-4 gap-y-1">
                        <span>Granted: {link.grantedAt ? new Date(link.grantedAt).toLocaleDateString() : 'Active'}</span>
                        <span>Scopes: {link.scopes.join(', ')}</span>
                      </div>

                      {/* Branding Delegation Toggle */}
                      {canManage && (
                        <div className="flex items-center gap-2 pt-1">
                          <input
                            type="checkbox"
                            id={`branding_${link.linkId}`}
                            checked={link.delegateBranding}
                            onChange={() => handleToggleBranding(link.linkId, link.delegateBranding)}
                            disabled={actionLoading === `branding_${link.linkId}`}
                            className="rounded border-border text-accent focus:ring-accent"
                          />
                          <label
                            htmlFor={`branding_${link.linkId}`}
                            className="text-xs text-text-secondary cursor-pointer select-none"
                          >
                            <span className="font-medium text-text-primary">Delegate Executive Report Branding</span>
                            {' '}(allow agency to apply its branding to your generated PDF reports)
                          </label>
                        </div>
                      )}
                    </div>

                    {canManage && (
                      <button
                        onClick={() => handleRevokeLink(link.linkId, link.agencyName)}
                        disabled={actionLoading === `revoke_${link.linkId}`}
                        className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-sev-critical/10 hover:bg-sev-critical/20 text-sev-critical border border-sev-critical/30 text-xs font-semibold transition-colors self-start sm:self-auto disabled:opacity-50"
                      >
                        {actionLoading === `revoke_${link.linkId}` ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <Trash2 className="w-3.5 h-3.5" />
                        )}
                        <span>Revoke Access</span>
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Section 3: Agency Access Audit Trail */}
          <div className="space-y-4 pt-4 border-t border-border">
            <div>
              <h2 className="text-lg font-bold text-text-primary">
                Agency Access Audit Trail
              </h2>
              <p className="text-xs text-text-secondary mt-0.5">
                Cryptographic audit trail tracking all cross-organization reads by external partner agencies (§2 & §3).
              </p>
            </div>

            {accessLogs.length === 0 ? (
              <div className="p-6 rounded-xl bg-surface border border-border text-center text-xs text-text-tertiary">
                No external agency accesses recorded yet.
              </div>
            ) : (
              <div className="overflow-x-auto rounded-xl border border-border bg-surface">
                <table className="w-full text-left text-xs">
                  <thead className="bg-surface-raised border-b border-border text-text-tertiary uppercase tracking-wider font-mono">
                    <tr>
                      <th className="px-4 py-3">Timestamp</th>
                      <th className="px-4 py-3">Agency</th>
                      <th className="px-4 py-3">Actor Email</th>
                      <th className="px-4 py-3">Accessed Endpoint</th>
                      <th className="px-4 py-3">Scope</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {accessLogs.map((log) => (
                      <tr key={log.id} className="hover:bg-surface-raised/40 transition-colors">
                        <td className="px-4 py-3 font-mono text-text-secondary whitespace-nowrap">
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                        <td className="px-4 py-3 font-medium text-text-primary">
                          {log.agencyName}
                        </td>
                        <td className="px-4 py-3 font-mono text-text-secondary">
                          {log.actor}
                        </td>
                        <td className="px-4 py-3 font-mono text-accent">
                          {log.path}
                        </td>
                        <td className="px-4 py-3">
                          <span className="px-1.5 py-0.5 rounded bg-surface-overlay border border-border text-text-tertiary font-mono text-[10px]">
                            {log.scopes.join(', ')}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
