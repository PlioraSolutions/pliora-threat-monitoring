'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import {
  Bell,
  RefreshCw,
  Loader2,
  CheckCircle2,
  Settings,
  Mail,
  AlertCircle,
  Clock,
} from 'lucide-react';
import { api } from '@/lib/client/api';
import { SeverityBadge } from '@/components/SeverityBadge';

interface AlertItem {
  id: string;
  eventType: string;
  severity: string;
  targetFqdn?: string;
  channel?: string;
  deliveryStatus: 'DELIVERED' | 'FAILED' | 'PENDING';
  recipients?: string[];
  createdAt: string;
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchAlerts = useCallback(async () => {
    try {
      const res = await api.get('/api/alerts');
      const list = res?.data || (Array.isArray(res) ? res : []);
      setAlerts(list);
    } catch (err) {
      console.error('Failed to load alerts:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-text-primary">
            Security Alert History
          </h1>
          <p className="text-caption text-text-secondary mt-0.5">
            Audit log of all high-confidence security alerts and incident notifications dispatched to team members.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              setRefreshing(true);
              fetchAlerts();
            }}
            disabled={refreshing}
            className="px-3.5 py-2 rounded-lg bg-surface border border-border hover:bg-surface-raised text-text-secondary hover:text-text-primary text-caption font-medium transition-colors flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          <Link
            href="/settings"
            className="px-4 py-2 rounded-lg bg-surface-raised hover:bg-surface-overlay text-text-primary text-caption font-semibold border border-border transition-colors flex items-center gap-1.5"
          >
            <Settings className="w-4 h-4 text-accent" />
            <span>Notification Preferences</span>
          </Link>
        </div>
      </div>

      {/* Alerts Table */}
      {loading ? (
        <div className="py-16 flex flex-col items-center justify-center space-y-3">
          <Loader2 className="w-8 h-8 text-accent animate-spin" />
          <p className="text-caption text-text-secondary">Loading alert history...</p>
        </div>
      ) : alerts.length === 0 ? (
        <div className="bg-surface border border-border rounded-xl p-12 text-center space-y-3">
          <Bell className="w-10 h-10 text-text-tertiary mx-auto" />
          <h3 className="text-body font-semibold text-text-primary">No alerts generated yet</h3>
          <p className="text-caption text-text-secondary max-w-sm mx-auto">
            Alerts are strictly dispatched for corroborated, high-confidence security events to avoid email fatigue.
          </p>
          <Link
            href="/settings"
            className="inline-flex items-center gap-1.5 text-accent text-caption font-semibold hover:underline mt-2"
          >
            Configure alert rules in Settings →
          </Link>
        </div>
      ) : (
        <div className="bg-surface border border-border rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-body border-collapse">
              <thead>
                <tr className="bg-surface-raised border-b border-border text-caption font-semibold text-text-tertiary uppercase tracking-wider">
                  <th className="py-3.5 px-4">Event Type</th>
                  <th className="py-3.5 px-4">Target Asset</th>
                  <th className="py-3.5 px-4">Severity</th>
                  <th className="py-3.5 px-4">Channel</th>
                  <th className="py-3.5 px-4">Delivery</th>
                  <th className="py-3.5 px-4">Dispatched At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {alerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-surface-raised/50 transition-colors">
                    <td className="py-4 px-4 font-semibold text-text-primary">
                      {alert.eventType.replace(/_/g, ' ')}
                    </td>

                    <td className="py-4 px-4 font-mono text-caption text-text-secondary">
                      {alert.targetFqdn || '—'}
                    </td>

                    <td className="py-4 px-4 whitespace-nowrap">
                      <SeverityBadge severity={alert.severity} />
                    </td>

                    <td className="py-4 px-4 whitespace-nowrap">
                      <span className="inline-flex items-center gap-1 text-caption text-text-secondary">
                        <Mail className="w-3.5 h-3.5 text-text-tertiary" />
                        <span>Email</span>
                      </span>
                    </td>

                    <td className="py-4 px-4 whitespace-nowrap">
                      {alert.deliveryStatus === 'DELIVERED' ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-caption font-medium bg-sev-low/10 text-sev-low border border-sev-low/20">
                          <CheckCircle2 className="w-3 h-3" /> Delivered
                        </span>
                      ) : alert.deliveryStatus === 'FAILED' ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-caption font-medium bg-sev-critical/10 text-sev-critical border border-sev-critical/20">
                          <AlertCircle className="w-3 h-3" /> Failed
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-caption font-medium bg-surface-raised text-text-tertiary border border-border">
                          <Clock className="w-3 h-3" /> Pending
                        </span>
                      )}
                    </td>

                    <td className="py-4 px-4 text-caption text-text-tertiary whitespace-nowrap font-mono">
                      {new Date(alert.createdAt).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
