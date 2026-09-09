'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import {
  Settings,
  Users,
  Bell,
  Shield,
  Check,
  AlertCircle,
  Loader2,
  Save,
  Plus,
  CreditCard,
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { api } from '@/lib/client/api';
import { BillingOverview } from '@/components/dashboard/BillingOverview';

interface AlertSettings {
  minRiskScore: number;
  enabledTypes: string[];
  additionalEmails: string[];
}

interface TeamMember {
  id: string;
  name: string;
  email: string;
  role: string;
  joinedAt: string;
}

const ALL_ALERT_TYPES = [
  { id: 'NEW_CRITICAL_FINDING', label: 'Critical Severity Finding', desc: 'Active critical configuration flaws and expired TLS' },
  { id: 'NEW_HIGH_FINDING', label: 'Confirmed High Finding', desc: 'Directly corroborated high-risk exposures' },
  { id: 'THREAT_DETECTED', label: 'Brand Look-Alike Detected', desc: 'Corroborated typosquat with live DNS or mail records' },
  { id: 'SCAN_FAILED', label: 'Scan Pipeline Failure', desc: 'Operational diagnostic alerts if scanning hits errors' },
];

export default function SettingsPage() {
  const { user, organization, role } = useAuth();
  const canEdit = role === 'OWNER' || role === 'ADMIN';

  const [activeTab, setActiveTab] = useState<'ALERTS' | 'TEAM' | 'BILLING'>('ALERTS');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Alert settings state
  const [minRiskScore, setMinRiskScore] = useState<number>(70);
  const [enabledTypes, setEnabledTypes] = useState<string[]>([
    'NEW_CRITICAL_FINDING',
    'NEW_HIGH_FINDING',
    'THREAT_DETECTED',
  ]);
  const [emailsInput, setEmailsInput] = useState<string>('');

  // Team state
  const [members, setMembers] = useState<TeamMember[]>([]);

  const fetchSettings = useCallback(async () => {
    try {
      setLoading(true);
      const [settingsRes, membersRes] = await Promise.allSettled([
        api.get('/api/org/alert-settings'),
        api.get('/api/org/members'),
      ]);

      if (settingsRes.status === 'fulfilled') {
        const s = settingsRes.value;
        if (s) {
          setMinRiskScore(s.minRiskScore ?? 70);
          setEnabledTypes(s.enabledTypes || ['CRITICAL_FINDING', 'CONFIRMED_HIGH_FINDING', 'THREAT_DETECTED']);
          setEmailsInput((s.additionalEmails || []).join(', '));
        }
      }

      if (membersRes.status === 'fulfilled') {
        setMembers(membersRes.value || []);
      }
    } catch (err) {
      console.error('Failed to load settings:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSettings();
  }, [fetchSettings]);

  const handleSaveAlerts = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canEdit) return;

    setSaving(true);
    setError(null);
    setSaveSuccess(false);

    try {
      const parsedEmails = emailsInput
        .split(',')
        .map((e) => e.trim().toLowerCase())
        .filter((e) => e.length > 0);

      await api.patch('/api/org/alert-settings', {
        minRiskScore,
        enabledTypes,
        additionalEmails: parsedEmails,
      });

      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err: any) {
      setError(err.message || 'Failed to save alert preferences.');
    } finally {
      setSaving(false);
    }
  };

  const toggleAlertType = (typeId: string) => {
    if (!canEdit) return;
    setEnabledTypes((prev) =>
      prev.includes(typeId) ? prev.filter((t) => t !== typeId) : [...prev, typeId]
    );
  };

  return (
    <div className="max-w-4xl space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-text-primary">
          Organization Settings & Team
        </h1>
        <p className="text-caption text-text-secondary mt-0.5">
          Manage alert notifications, delivery thresholds, and access roles for {organization?.name}.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-border pb-2">
        <button
          onClick={() => setActiveTab('ALERTS')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-caption font-semibold transition-colors ${
            activeTab === 'ALERTS'
              ? 'bg-accent text-white shadow-sm'
              : 'text-text-secondary hover:text-text-primary hover:bg-surface-raised'
          }`}
        >
          <Bell className="w-4 h-4" />
          <span>Alert Preferences</span>
        </button>

        <button
          onClick={() => setActiveTab('TEAM')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-caption font-semibold transition-colors ${
            activeTab === 'TEAM'
              ? 'bg-accent text-white shadow-sm'
              : 'text-text-secondary hover:text-text-primary hover:bg-surface-raised'
          }`}
        >
          <Users className="w-4 h-4" />
          <span>Team Members ({members.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('BILLING')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-caption font-semibold transition-colors ${
            activeTab === 'BILLING'
              ? 'bg-accent text-white shadow-sm'
              : 'text-text-secondary hover:text-text-primary hover:bg-surface-raised'
          }`}
        >
          <CreditCard className="w-4 h-4" />
          <span>Billing & Plan</span>
        </button>

        <Link
          href="/settings/agency"
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-caption font-semibold transition-colors text-text-secondary hover:text-text-primary hover:bg-surface-raised"
        >
          <Shield className="w-4 h-4 text-accent" />
          <span>Partner Agencies</span>
        </Link>
      </div>

      {loading ? (
        <div className="py-16 flex flex-col items-center justify-center space-y-3">
          <Loader2 className="w-8 h-8 text-accent animate-spin" />
          <p className="text-caption text-text-secondary">Loading settings...</p>
        </div>
      ) : activeTab === 'ALERTS' ? (
        /* Tab 1: Alert Preferences */
        <div className="bg-surface border border-border rounded-xl p-6 sm:p-8 space-y-6 shadow-sm">
          {!canEdit && (
            <div className="p-3.5 bg-surface-raised border border-border rounded-lg text-caption text-text-tertiary">
              <span className="font-semibold text-text-secondary">Read-only mode:</span> Your organization role ({role}) cannot modify alert settings. Only Owner or Admin accounts can save changes.
            </div>
          )}

          {error && (
            <div className="p-3.5 bg-sev-critical/10 border border-sev-critical/30 rounded-lg text-sev-critical text-caption flex items-center gap-2">
              <AlertCircle className="w-4 h-4" />
              <span>{error}</span>
            </div>
          )}

          {saveSuccess && (
            <div className="p-3.5 bg-sev-low/10 border border-sev-low/30 rounded-lg text-sev-low text-caption flex items-center gap-2">
              <Check className="w-4 h-4" />
              <span>Alert preferences saved successfully!</span>
            </div>
          )}

          <form onSubmit={handleSaveAlerts} className="space-y-6">
            {/* Risk Score Threshold */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-body font-semibold text-text-primary">
                  Minimum Risk Score for Immediate Email Alerts
                </label>
                <span className="text-body font-bold font-mono text-accent">
                  {minRiskScore} / 100
                </span>
              </div>
              <p className="text-caption text-text-secondary">
                Findings with a computed risk score below this threshold will be visible on your dashboard but will not dispatch emergency emails.
              </p>
              <input
                type="range"
                min="30"
                max="95"
                step="5"
                disabled={!canEdit}
                value={minRiskScore}
                onChange={(e) => setMinRiskScore(Number(e.target.value))}
                className="w-full accent-accent cursor-pointer"
              />
              <div className="flex justify-between text-[11px] text-text-tertiary font-mono">
                <span>30 (More alerts)</span>
                <span>70 (Default balanced)</span>
                <span>95 (Critical only)</span>
              </div>
            </div>

            {/* Enabled Alert Types */}
            <div className="space-y-3 pt-4 border-t border-border">
              <div className="text-body font-semibold text-text-primary">
                Enabled Security Event Categories
              </div>
              <div className="space-y-2.5">
                {ALL_ALERT_TYPES.map((type) => {
                  const isChecked = enabledTypes.includes(type.id);
                  return (
                    <div
                      key={type.id}
                      onClick={() => toggleAlertType(type.id)}
                      className={`p-3.5 rounded-lg border flex items-start gap-3 transition-colors ${
                        canEdit ? 'cursor-pointer hover:bg-surface-raised' : 'opacity-70'
                      } ${isChecked ? 'bg-surface-raised border-accent/40' : 'border-border'}`}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        disabled={!canEdit}
                        onChange={() => {}}
                        className="mt-1 accent-accent"
                      />
                      <div>
                        <div className="text-body font-medium text-text-primary">{type.label}</div>
                        <div className="text-caption text-text-secondary">{type.desc}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Additional Email Recipient List */}
            <div className="space-y-2 pt-4 border-t border-border">
              <label className="text-body font-semibold text-text-primary block">
                Additional Notification Recipients
              </label>
              <p className="text-caption text-text-secondary">
                By default, all organization Owners and Admins receive security notifications. Add comma-separated emails for auxiliary recipients (e.g. MSP or security on-call):
              </p>
              <input
                type="text"
                disabled={!canEdit}
                value={emailsInput}
                onChange={(e) => setEmailsInput(e.target.value)}
                placeholder="oncall@company.com, alerts@managedsec.net"
                className="w-full px-4 py-2.5 bg-surface-raised border border-border rounded-lg text-body text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none transition-colors"
              />
            </div>

            {/* Submit button */}
            {canEdit && (
              <div className="pt-2 flex justify-end">
                <button
                  type="submit"
                  disabled={saving}
                  className="px-5 py-2.5 rounded-lg bg-accent hover:bg-accent-hover text-white font-semibold text-body transition-colors flex items-center gap-2 shadow-sm disabled:opacity-50"
                >
                  {saving ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Save className="w-4 h-4" />
                  )}
                  <span>{saving ? 'Saving...' : 'Save Preferences'}</span>
                </button>
              </div>
            )}
          </form>
        </div>
      ) : activeTab === 'TEAM' ? (
        /* Tab 2: Team Members */
        <div className="space-y-6">
          <div className="bg-surface border border-border rounded-xl overflow-hidden shadow-sm">
            <table className="w-full text-left text-body border-collapse">
              <thead>
                <tr className="bg-surface-raised border-b border-border text-caption font-semibold text-text-tertiary uppercase tracking-wider">
                  <th className="py-3.5 px-4">Member Name</th>
                  <th className="py-3.5 px-4">Email</th>
                  <th className="py-3.5 px-4">Role</th>
                  <th className="py-3.5 px-4">Joined Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {members.map((m) => (
                  <tr key={m.id} className="hover:bg-surface-raised/50 transition-colors">
                    <td className="py-4 px-4 font-semibold text-text-primary">
                      {m.name}
                      {m.id === user?.id && (
                        <span className="ml-2 text-[10px] font-mono px-1.5 py-0.5 rounded bg-accent/10 text-accent border border-accent/20">
                          You
                        </span>
                      )}
                    </td>
                    <td className="py-4 px-4 text-caption text-text-secondary">
                      {m.email}
                    </td>
                    <td className="py-4 px-4">
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-caption font-semibold bg-surface-raised border border-border">
                        <Shield className="w-3 h-3 text-accent" />
                        <span>{m.role}</span>
                      </span>
                    </td>
                    <td className="py-4 px-4 text-caption text-text-tertiary font-mono">
                      {new Date(m.joinedAt).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Role Permissions Legend */}
          <div className="bg-surface border border-border rounded-xl p-5 space-y-3">
            <h3 className="text-caption font-semibold text-text-secondary uppercase tracking-wider">
              Role Capabilities Matrix
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-caption text-text-secondary">
              <div className="p-3 bg-surface-raised rounded-lg border border-border space-y-1">
                <span className="font-bold text-text-primary block">OWNER & ADMIN</span>
                <p>Full control: Add & verify domains, trigger scans, change finding status, manage alert rules, and view team.</p>
              </div>
              <div className="p-3 bg-surface-raised rounded-lg border border-border space-y-1">
                <span className="font-bold text-text-primary block">MEMBER</span>
                <p>Operational access: View all assets, inspect findings and AI explanations, trigger discovery sweeps.</p>
              </div>
              <div className="p-3 bg-surface-raised rounded-lg border border-border space-y-1">
                <span className="font-bold text-text-primary block">VIEWER</span>
                <p>Auditor access: Read-only visibility. Remediation, scan triggering, and setting mutations are disabled.</p>
              </div>
            </div>
          </div>
        </div>
      ) : activeTab === 'BILLING' ? (
        <BillingOverview canEdit={canEdit} />
      ) : null}
    </div>
  );
}
