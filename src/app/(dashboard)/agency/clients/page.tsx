'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import {
  Users,
  Shield,
  AlertTriangle,
  FileDown,
  ExternalLink,
  Plus,
  Loader2,
  CheckCircle2,
  AlertCircle,
  Clock,
  Trash2,
  Search,
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';

interface ClientSummary {
  linkId: string;
  clientOrgId: string;
  name: string;
  slug: string;
  plan: string;
  riskScore: number;
  securityPosture: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  openCriticalCount: number;
  openHighCount: number;
  totalFindings: number;
  lastScanDate: string | null;
  delegateBranding: boolean;
  linkedAt: string;
}

export default function AgencyClientsPage() {
  const { user, organization, role } = useAuth();
  const isAgency = organization?.accountType === 'AGENCY';
  const canManage = role === 'OWNER' || role === 'ADMIN';

  const [clients, setClients] = useState<ClientSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [error, setError] = useState<string | null>(null);

  // Invite modal state
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [inviteSlugOrId, setInviteSlugOrId] = useState('');
  const [inviteDelegateBranding, setInviteDelegateBranding] = useState(true);
  const [inviteSubmitting, setInviteSubmitting] = useState(false);
  const [inviteError, setInviteError] = useState<string | null>(null);
  const [inviteSuccess, setInviteSuccess] = useState<string | null>(null);

  // Revoke state
  const [revokingLinkId, setRevokingLinkId] = useState<string | null>(null);

  const fetchClients = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetch('/api/agency/clients');
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error?.message || 'Failed to fetch managed clients');
      }

      setClients(data.data?.clients || []);
    } catch (err: any) {
      setError(err.message || 'Error loading client portfolio');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchClients();
  }, [fetchClients]);

  const handleSendInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inviteSlugOrId.trim()) return;

    try {
      setInviteSubmitting(true);
      setInviteError(null);
      setInviteSuccess(null);

      const res = await fetch('/api/agency/invites', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          clientOrgSlugOrId: inviteSlugOrId.trim(),
          delegateBranding: inviteDelegateBranding,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error?.message || 'Failed to send invitation');
      }

      setInviteSuccess(`Invitation sent to ${data.data?.clientOrgName || inviteSlugOrId}. Status is PENDING approval.`);
      setInviteSlugOrId('');
      fetchClients();
    } catch (err: any) {
      setInviteError(err.message || 'Failed to send invite');
    } finally {
      setInviteSubmitting(false);
    }
  };

  const handleRevokeLink = async (linkId: string, clientName: string) => {
    if (!confirm(`Are you sure you want to revoke access to ${clientName}? This will immediately terminate agency access.`)) {
      return;
    }

    try {
      setRevokingLinkId(linkId);
      const res = await fetch(`/api/agency/clients/${linkId}/revoke`, {
        method: 'POST',
      });
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error?.message || 'Failed to revoke link');
      }

      // Update state locally
      setClients((prev) => prev.filter((c) => c.linkId !== linkId));
    } catch (err: any) {
      alert(err.message || 'Error revoking link');
    } finally {
      setRevokingLinkId(null);
    }
  };

  const filteredClients = clients.filter((c) =>
    c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    c.slug.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case 'A': return 'text-sev-low bg-sev-low/10 border-sev-low/20';
      case 'B': return 'text-sev-medium bg-sev-medium/10 border-sev-medium/20';
      case 'C': return 'text-sev-high bg-sev-high/10 border-sev-high/20';
      case 'D':
      case 'F': return 'text-sev-critical bg-sev-critical/10 border-sev-critical/20';
      default: return 'text-text-secondary bg-surface-overlay border-border';
    }
  };

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-12">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-accent/10 border border-accent/20 flex items-center justify-center text-accent">
              <Users className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-text-primary">
                Agency Client Portfolio
              </h1>
              <p className="text-body text-text-secondary text-sm">
                Unified visibility into managed client organizations with read-only scoped delegation and white-label reporting.
              </p>
            </div>
          </div>
        </div>

        {canManage && (
          <button
            onClick={() => {
              setShowInviteModal(true);
              setInviteError(null);
              setInviteSuccess(null);
            }}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-accent hover:bg-accent-hover text-white text-body font-medium transition-colors shadow-sm self-start sm:self-auto"
          >
            <Plus className="w-4 h-4" />
            <span>Invite Client Organization</span>
          </button>
        )}
      </div>

      {/* Account Type Warning if accessed by standard org */}
      {!isAgency && (
        <div className="p-4 rounded-lg bg-sev-medium/10 border border-sev-medium/30 text-sev-medium flex items-start gap-3">
          <AlertCircle className="w-5 h-5 mt-0.5 shrink-0" />
          <div className="text-sm">
            <p className="font-semibold">Standard Account Notice</p>
            <p className="mt-0.5 text-text-secondary">
              Your organization is currently registered as a Standard account. To manage client organizations as a certified MSP or agency partner, your organization accountType must be set to AGENCY.
            </p>
          </div>
        </div>
      )}

      {/* Controls & Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="relative w-full sm:w-96">
          <Search className="w-4 h-4 text-text-tertiary absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search managed clients by name or slug..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-surface border border-border text-sm text-text-primary focus:outline-none focus:border-accent"
          />
        </div>

        <div className="text-xs text-text-secondary">
          Active Managed Clients: <span className="font-mono font-bold text-text-primary">{clients.length}</span>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-4 rounded-lg bg-sev-critical/10 border border-sev-critical/30 text-sev-critical text-sm">
          {error}
        </div>
      )}

      {/* Loading state */}
      {loading ? (
        <div className="py-20 flex flex-col items-center justify-center text-text-secondary">
          <Loader2 className="w-8 h-8 animate-spin text-accent mb-3" />
          <p className="text-sm">Loading managed client portfolio...</p>
        </div>
      ) : filteredClients.length === 0 ? (
        /* Empty State */
        <div className="text-center py-16 px-4 bg-surface border border-border rounded-xl space-y-4">
          <div className="w-12 h-12 rounded-full bg-surface-overlay border border-border flex items-center justify-center mx-auto text-text-tertiary">
            <Users className="w-6 h-6" />
          </div>
          <div className="max-w-md mx-auto">
            <h3 className="text-base font-semibold text-text-primary">No Active Client Organizations</h3>
            <p className="text-sm text-text-secondary mt-1">
              {searchQuery
                ? 'No client organizations match your filter.'
                : 'Send an invitation to a client organization to begin cross-organization monitoring.'}
            </p>
          </div>
          {!searchQuery && canManage && (
            <button
              onClick={() => setShowInviteModal(true)}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-accent hover:bg-accent-hover text-white text-sm font-medium transition-colors"
            >
              <Plus className="w-4 h-4" />
              <span>Invite First Client</span>
            </button>
          )}
        </div>
      ) : (
        /* Clients Portfolio Grid */
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredClients.map((client) => (
            <div
              key={client.linkId}
              className="bg-surface border border-border rounded-xl p-5 hover:border-border-focus transition-all flex flex-col justify-between space-y-5 shadow-sm"
            >
              {/* Card Header */}
              <div>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h3 className="font-semibold text-text-primary text-base flex items-center gap-2">
                      {client.name}
                    </h3>
                    <p className="text-xs text-text-tertiary font-mono mt-0.5">
                      slug: {client.slug} • plan: {client.plan}
                    </p>
                  </div>

                  <div className={`px-2.5 py-1 rounded-lg border font-mono font-bold text-sm ${getGradeColor(client.grade)}`}>
                    Grade {client.grade}
                  </div>
                </div>

                {/* Score and Posture Bar */}
                <div className="mt-4 p-3 rounded-lg bg-surface-overlay border border-border/60">
                  <div className="flex justify-between text-xs mb-1.5">
                    <span className="text-text-secondary">Security Posture</span>
                    <span className="font-mono font-bold text-text-primary">{client.securityPosture}%</span>
                  </div>
                  <div className="w-full h-2 rounded-full bg-surface overflow-hidden">
                    <div
                      className="h-full bg-accent rounded-full transition-all duration-500"
                      style={{ width: `${client.securityPosture}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[11px] text-text-tertiary mt-2">
                    <span>Risk Score: <strong className="text-text-secondary font-mono">{client.riskScore}/100</strong></span>
                    {client.delegateBranding && (
                      <span className="text-accent font-medium">★ Brand Delegated</span>
                    )}
                  </div>
                </div>

                {/* Open Findings Counters */}
                <div className="grid grid-cols-3 gap-2 mt-3 text-center">
                  <div className="p-2 rounded bg-sev-critical/5 border border-sev-critical/20">
                    <div className="text-base font-bold font-mono text-sev-critical">
                      {client.openCriticalCount}
                    </div>
                    <div className="text-[10px] uppercase tracking-wider text-text-tertiary">Critical</div>
                  </div>
                  <div className="p-2 rounded bg-sev-high/5 border border-sev-high/20">
                    <div className="text-base font-bold font-mono text-sev-high">
                      {client.openHighCount}
                    </div>
                    <div className="text-[10px] uppercase tracking-wider text-text-tertiary">High</div>
                  </div>
                  <div className="p-2 rounded bg-surface-overlay border border-border">
                    <div className="text-base font-bold font-mono text-text-primary">
                      {client.totalFindings}
                    </div>
                    <div className="text-[10px] uppercase tracking-wider text-text-tertiary">Total Open</div>
                  </div>
                </div>

                {/* Meta details */}
                <div className="mt-3 text-[11px] text-text-tertiary flex items-center gap-1.5">
                  <Clock className="w-3 h-3" />
                  <span>
                    Last Scan: {client.lastScanDate ? new Date(client.lastScanDate).toLocaleDateString() : 'Never'}
                  </span>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="pt-3 border-t border-border/60 flex flex-col gap-2">
                <div className="grid grid-cols-2 gap-2">
                  <Link
                    href={`/findings?clientOrgId=${client.clientOrgId}`}
                    className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-surface-raised hover:bg-surface-overlay text-text-primary text-xs font-medium border border-border transition-colors text-center"
                  >
                    <span>View Findings</span>
                    <ExternalLink className="w-3 h-3 text-text-tertiary" />
                  </Link>

                  <a
                    href={`/api/reports/export?clientOrgId=${client.clientOrgId}&format=pdf`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-accent/10 hover:bg-accent/20 text-accent text-xs font-medium border border-accent/20 transition-colors text-center"
                  >
                    <FileDown className="w-3 h-3" />
                    <span>Branded PDF</span>
                  </a>
                </div>

                {canManage && (
                  <button
                    onClick={() => handleRevokeLink(client.linkId, client.name)}
                    disabled={revokingLinkId === client.linkId}
                    className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg text-sev-critical/80 hover:text-sev-critical hover:bg-sev-critical/10 text-[11px] transition-colors"
                  >
                    {revokingLinkId === client.linkId ? (
                      <Loader2 className="w-3 h-3 animate-spin" />
                    ) : (
                      <Trash2 className="w-3 h-3" />
                    )}
                    <span>Revoke Agency Link</span>
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Invite Modal */}
      {showInviteModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl max-w-md w-full p-6 space-y-5 shadow-2xl">
            <div className="flex justify-between items-start">
              <div>
                <h3 className="text-lg font-bold text-text-primary">Invite Client Organization</h3>
                <p className="text-xs text-text-secondary mt-1">
                  Sends an invitation for read-only security visibility. The client Owner or Admin must approve before access is granted.
                </p>
              </div>
              <button
                onClick={() => setShowInviteModal(false)}
                className="text-text-tertiary hover:text-text-primary text-sm p-1"
              >
                ✕
              </button>
            </div>

            {inviteError && (
              <div className="p-3 rounded bg-sev-critical/10 border border-sev-critical/30 text-sev-critical text-xs">
                {inviteError}
              </div>
            )}

            {inviteSuccess && (
              <div className="p-3 rounded bg-sev-low/10 border border-sev-low/30 text-sev-low text-xs flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                <span>{inviteSuccess}</span>
              </div>
            )}

            <form onSubmit={handleSendInvite} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-text-primary mb-1">
                  Client Organization Slug or ID
                </label>
                <input
                  type="text"
                  placeholder="e.g. acme-corp or org-12345"
                  value={inviteSlugOrId}
                  onChange={(e) => setInviteSlugOrId(e.target.value)}
                  required
                  className="w-full px-3 py-2 rounded-lg bg-surface-raised border border-border text-sm text-text-primary focus:outline-none focus:border-accent"
                />
              </div>

              <div className="flex items-start gap-2.5 p-3 rounded-lg bg-surface-overlay border border-border">
                <input
                  type="checkbox"
                  id="delegateBranding"
                  checked={inviteDelegateBranding}
                  onChange={(e) => setInviteDelegateBranding(e.target.checked)}
                  className="mt-0.5"
                />
                <label htmlFor="delegateBranding" className="text-xs text-text-secondary cursor-pointer">
                  <span className="font-semibold text-text-primary block">Request Report White-Labeling Delegation</span>
                  Apply your agency's branding on client executive PDF summaries (if client plan allows white-labeling).
                </label>
              </div>

              <div className="pt-2 flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowInviteModal(false)}
                  className="px-4 py-2 rounded-lg bg-surface-raised hover:bg-surface-overlay text-text-secondary text-sm font-medium transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={inviteSubmitting}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg bg-accent hover:bg-accent-hover text-white text-sm font-medium transition-colors disabled:opacity-50"
                >
                  {inviteSubmitting && <Loader2 className="w-4 h-4 animate-spin" />}
                  <span>Send Invitation</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
