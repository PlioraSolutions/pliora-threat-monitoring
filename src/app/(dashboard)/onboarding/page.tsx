'use client';

import React, { useState, useEffect, Suspense } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  Globe,
  ShieldCheck,
  Copy,
  Check,
  AlertCircle,
  Loader2,
  ArrowRight,
  RefreshCw,
  Zap,
  Lock,
} from 'lucide-react';
import { api } from '@/lib/client/api';
import { useAuth } from '@/context/AuthContext';

function OnboardingContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { role } = useAuth();

  const paramId = searchParams.get('id');
  const paramDomain = searchParams.get('domain');

  const [domainInput, setDomainInput] = useState('');
  const [importance, setImportance] = useState('HIGH');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Asset verification state
  const [createdAsset, setCreatedAsset] = useState<any | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [fastTrackLoading, setFastTrackLoading] = useState(false);
  const [fastTrackAccepted, setFastTrackAccepted] = useState(false);
  const [verifyResult, setVerifyResult] = useState<{
    success: boolean;
    message?: string;
  } | null>(null);

  const [copiedTxtHost, setCopiedTxtHost] = useState(false);
  const [copiedTxtValue, setCopiedTxtValue] = useState(false);
  const [copiedHttpPath, setCopiedHttpPath] = useState(false);
  const [copiedHttpBody, setCopiedHttpBody] = useState(false);

  // On mount, if domain or id parameter was passed, pre-load asset
  useEffect(() => {
    if (paramDomain) {
      setDomainInput(paramDomain);
    }

    if (paramId || paramDomain) {
      api.get('/api/assets')
        .then((res) => {
          const list = Array.isArray(res) ? res : res?.data || [];
          const found = list.find(
            (a: any) =>
              (paramId && (a._id === paramId || a.id === paramId)) ||
              (paramDomain && (a.fqdn === paramDomain || a.rootDomain === paramDomain))
          );
          if (found) {
            setCreatedAsset(found);
          }
        })
        .catch(() => {});
    }
  }, [paramId, paramDomain]);

  const handleAddDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanDomain = domainInput
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '');

    if (!cleanDomain) {
      setError('Please enter a valid fully-qualified domain name (e.g., example.com).');
      return;
    }

    setError(null);
    setSubmitting(true);
    setVerifyResult(null);

    try {
      const asset = await api.post('/api/assets', {
        domain: cleanDomain,
        importance,
      });
      setCreatedAsset(asset);
    } catch (err: any) {
      if (err.message?.toLowerCase().includes('already registered')) {
        // Automatically fetch and load the already registered asset
        try {
          const listRes = await api.get('/api/assets');
          const list = Array.isArray(listRes) ? listRes : listRes?.data || [];
          const existing = list.find(
            (a: any) => a.fqdn === cleanDomain || a.rootDomain === cleanDomain
          );
          if (existing) {
            setCreatedAsset(existing);
            return;
          }
        } catch {}
      }

      if (err.status === 400 && err.message?.toLowerCase().includes('plan')) {
        setError('Domain quota reached for your plan. Upgrade in Settings or contact support.');
      } else {
        setError(err.message || 'Failed to add domain. Please try again.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleCheckVerification = async () => {
    if (!createdAsset) return;
    setVerifying(true);
    setVerifyResult(null);

    try {
      const id = createdAsset.id || createdAsset._id;
      const res = await api.post(`/api/assets/${id}/verify`);
      if (res?.verified || res?.verificationStatus === 'VERIFIED') {
        setVerifyResult({
          success: true,
          message: 'Ownership confirmed! Subdomain discovery and automated exposure checks are running.',
        });
        setCreatedAsset((prev: any) => ({ ...prev, verificationStatus: 'VERIFIED' }));
      } else {
        setVerifyResult({
          success: false,
          message:
            res?.message ||
            res?.reason ||
            'Verification token not detected yet. DNS records may take a few minutes to propagate across the globe.',
        });
      }
    } catch (err: any) {
      setVerifyResult({
        success: false,
        message:
          err.message ||
          'Verification attempt failed. Please check that your DNS record has propagated and retry.',
      });
    } finally {
      setVerifying(false);
    }
  };

  const handleFastTrackVerify = async () => {
    if (!createdAsset || !fastTrackAccepted) return;
    setFastTrackLoading(true);
    setVerifyResult(null);

    try {
      const id = createdAsset.id || createdAsset._id;
      const res = await api.post(`/api/assets/${id}/verify`, {
        fastTrack: true,
        authorized: true,
      });

      if (res?.verified || res?.verificationStatus === 'VERIFIED') {
        setVerifyResult({
          success: true,
          message: 'Ownership confirmed via Administrator Authorization! Subdomain discovery and exposure sweeps are running.',
        });
        setCreatedAsset((prev: any) => ({ ...prev, verificationStatus: 'VERIFIED' }));
      } else {
        setVerifyResult({
          success: false,
          message: res?.message || 'Fast-track verification failed. Please try again.',
        });
      }
    } catch (err: any) {
      setVerifyResult({
        success: false,
        message: err.message || 'Verification attempt failed.',
      });
    } finally {
      setFastTrackLoading(false);
    }
  };

  const copyToClipboard = (text: string, setter: (val: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setter(true);
    setTimeout(() => setter(false), 2000);
  };

  const domain = createdAsset?.fqdn || createdAsset?.rootDomain || domainInput.trim().toLowerCase();
  const token = createdAsset?.verificationToken || '';
  const txtHost = `_pliora-challenge.${domain}`;
  const txtValue = token;
  const httpPath = `https://${domain}/.well-known/pliora-challenge`;
  const httpBody = token;

  return (
    <div className="max-w-3xl mx-auto space-y-8 py-4">
      {/* Page Title */}
      <div className="space-y-1">
        <h1 className="text-2xl font-bold tracking-tight text-text-primary">
          Add & Verify Monitored Domain
        </h1>
        <p className="text-caption text-text-secondary">
          Confirm ownership of your root domain to initiate automated passive discovery and exposure analysis.
        </p>
      </div>

      {/* Step 1: Domain Input Form */}
      {!createdAsset ? (
        <div className="bg-surface border border-border rounded-xl p-6 sm:p-8 space-y-6 shadow-sm">
          {error && (
            <div className="p-3.5 bg-sev-critical/10 border border-sev-critical/30 rounded-lg flex items-start gap-2.5 text-sev-critical text-caption">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleAddDomain} className="space-y-5">
            <div>
              <label className="block text-caption font-semibold text-text-secondary uppercase tracking-wider mb-1.5">
                Root Domain Name
              </label>
              <div className="relative">
                <input
                  type="text"
                  required
                  value={domainInput}
                  onChange={(e) => setDomainInput(e.target.value)}
                  placeholder="acme.com or yourcompany.org"
                  className="w-full px-4 py-3 bg-surface-raised border border-border rounded-lg text-body text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none transition-colors font-mono"
                />
              </div>
              <p className="text-[12px] text-text-tertiary mt-1.5">
                Do not include protocol (https://) or subdomains. Subdomains will be automatically discovered via Certificate Transparency logs.
              </p>
            </div>

            <div>
              <label className="block text-caption font-semibold text-text-secondary uppercase tracking-wider mb-1.5">
                Business Criticality
              </label>
              <select
                value={importance}
                onChange={(e) => setImportance(e.target.value)}
                className="w-full px-4 py-2.5 bg-surface-raised border border-border rounded-lg text-body text-text-primary focus:border-accent focus:outline-none transition-colors"
              >
                <option value="CRITICAL">Critical (Primary public domain, customer login, core SaaS)</option>
                <option value="HIGH">High (Important operational or brand asset)</option>
                <option value="NORMAL">Normal (Standard corporate asset)</option>
                <option value="LOW">Low (Auxiliary or non-critical domain)</option>
              </select>
              <p className="text-[12px] text-text-tertiary mt-1.5">
                Assets marked Critical carry higher weight in organization risk score calculations.
              </p>
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="w-full flex items-center justify-center gap-2 py-3 px-6 rounded-lg bg-accent hover:bg-accent-hover text-white font-semibold text-body transition-colors shadow-sm disabled:opacity-50"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Configuring Asset...</span>
                </>
              ) : (
                <>
                  <span>Continue to Domain Verification</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>
        </div>
      ) : (
        /* Step 2: Verification Challenge Display */
        <div className="space-y-6">
          {/* Status feedback */}
          {verifyResult && (
            <div
              className={`p-4 rounded-xl border flex items-start gap-3 ${
                verifyResult.success
                  ? 'bg-sev-low/10 border-sev-low/30 text-sev-low'
                  : 'bg-sev-high/10 border-sev-high/30 text-sev-high'
              }`}
            >
              {verifyResult.success ? (
                <ShieldCheck className="w-5 h-5 shrink-0 mt-0.5" />
              ) : (
                <AlertCircle className="w-5 h-5 shrink-0 mt-0.5" />
              )}
              <div className="text-body leading-relaxed">
                <strong className="block font-semibold">
                  {verifyResult.success ? 'Verification Successful!' : 'Verification Pending'}
                </strong>
                <span className="text-caption text-text-secondary mt-0.5 block">
                  {verifyResult.message}
                </span>
              </div>
            </div>
          )}

          {createdAsset.verificationStatus === 'VERIFIED' ? (
            /* Success State */
            <div className="bg-surface border border-sev-low/30 rounded-xl p-8 text-center space-y-6">
              <div className="w-14 h-14 rounded-full bg-sev-low/10 text-sev-low mx-auto flex items-center justify-center">
                <ShieldCheck className="w-8 h-8" />
              </div>

              <div className="space-y-2 max-w-md mx-auto">
                <h2 className="text-xl font-bold text-text-primary">
                  {domain} is Verified
                </h2>
                <p className="text-caption text-text-secondary leading-relaxed">
                  PLIŌRA is now passively enumerating subdomains from Certificate Transparency logs and queueing full exposure sweeps.
                </p>
              </div>

              <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
                <Link
                  href="/dashboard"
                  className="px-5 py-2.5 rounded-lg bg-accent hover:bg-accent-hover text-white font-semibold text-body transition-colors flex items-center gap-2 shadow"
                >
                  <span>Go to Command Center</span>
                  <ArrowRight className="w-4 h-4" />
                </Link>

                <Link
                  href="/assets"
                  className="px-5 py-2.5 rounded-lg bg-surface-raised border border-border hover:bg-surface-overlay text-text-primary font-medium text-body transition-colors"
                >
                  <span>View Asset Inventory</span>
                </Link>
              </div>
            </div>
          ) : (
            /* Challenge Card */
            <div className="bg-surface border border-border rounded-xl p-6 sm:p-8 space-y-6 shadow-sm">
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-caption text-text-tertiary uppercase font-mono tracking-wider">
                    Target Domain
                  </span>
                  <span className="text-caption px-2 py-0.5 rounded bg-sev-medium/10 text-sev-medium font-semibold border border-sev-medium/20">
                    Awaiting Verification
                  </span>
                </div>
                <h2 className="text-xl font-mono font-bold text-text-primary">{domain}</h2>
              </div>

              {/* Option A: DNS TXT (Recommended) */}
              <div className="space-y-3 p-4 bg-surface-raised border border-border rounded-lg">
                <div className="flex items-center justify-between">
                  <span className="text-body font-semibold text-text-primary flex items-center gap-2">
                    <span>Option A: Add DNS TXT Record</span>
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-accent/10 text-accent border border-accent/20">
                      Standard
                    </span>
                  </span>
                </div>

                <p className="text-caption text-text-secondary">
                  Add the following TXT record to your domain's DNS manager (e.g. Cloudflare, Route53, GoDaddy):
                </p>

                <div className="space-y-2 pt-1 font-mono text-caption">
                  {/* Hostname */}
                  <div>
                    <span className="text-text-tertiary block text-[11px] mb-1">Host / Name</span>
                    <div className="flex items-center justify-between bg-mono-bg border border-mono-border rounded p-2.5 text-text-primary">
                      <span className="break-all">{txtHost}</span>
                      <button
                        onClick={() => copyToClipboard(txtHost, setCopiedTxtHost)}
                        className="ml-2 text-text-tertiary hover:text-text-primary flex items-center gap-1 shrink-0"
                      >
                        {copiedTxtHost ? <Check className="w-3.5 h-3.5 text-sev-low" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  {/* TXT Value */}
                  <div>
                    <span className="text-text-tertiary block text-[11px] mb-1">Value / Target</span>
                    <div className="flex items-center justify-between bg-mono-bg border border-mono-border rounded p-2.5 text-text-primary">
                      <span className="break-all">{txtValue}</span>
                      <button
                        onClick={() => copyToClipboard(txtValue, setCopiedTxtValue)}
                        className="ml-2 text-text-tertiary hover:text-text-primary flex items-center gap-1 shrink-0"
                      >
                        {copiedTxtValue ? <Check className="w-3.5 h-3.5 text-sev-low" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Option B: HTTP Well-Known */}
              <div className="space-y-3 p-4 bg-surface-raised border border-border rounded-lg">
                <div className="flex items-center justify-between">
                  <span className="text-body font-semibold text-text-primary">
                    Option B: HTTP Well-Known Challenge
                  </span>
                </div>

                <p className="text-caption text-text-secondary">
                  If you have direct web server access, host the token at this URL:
                </p>

                <div className="space-y-2 pt-1 font-mono text-caption">
                  <div>
                    <span className="text-text-tertiary block text-[11px] mb-1">HTTP Endpoint</span>
                    <div className="flex items-center justify-between bg-mono-bg border border-mono-border rounded p-2.5 text-text-primary">
                      <span className="break-all">{httpPath}</span>
                      <button
                        onClick={() => copyToClipboard(httpPath, setCopiedHttpPath)}
                        className="ml-2 text-text-tertiary hover:text-text-primary flex items-center gap-1 shrink-0"
                      >
                        {copiedHttpPath ? <Check className="w-3.5 h-3.5 text-sev-low" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  <div>
                    <span className="text-text-tertiary block text-[11px] mb-1">Expected Response Body</span>
                    <div className="flex items-center justify-between bg-mono-bg border border-mono-border rounded p-2.5 text-text-primary">
                      <span className="break-all">{httpBody}</span>
                      <button
                        onClick={() => copyToClipboard(httpBody, setCopiedHttpBody)}
                        className="ml-2 text-text-tertiary hover:text-text-primary flex items-center gap-1 shrink-0"
                      >
                        {copiedHttpBody ? <Check className="w-3.5 h-3.5 text-sev-low" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Option C: Fast-Track Administrator Authorization */}
              <div className="space-y-3 p-4 bg-accent/5 border border-accent/20 rounded-lg">
                <div className="flex items-center justify-between">
                  <span className="text-body font-semibold text-accent flex items-center gap-2">
                    <Zap className="w-4 h-4" />
                    <span>Option C: Fast-Track / Instant Authorization</span>
                  </span>
                  <span className="text-[11px] font-semibold px-2 py-0.5 rounded bg-accent/15 text-accent border border-accent/30">
                    Instant
                  </span>
                </div>

                <p className="text-caption text-text-secondary">
                  Evaluating or need immediate scanning without waiting for DNS propagation? As an administrator, you can certify domain authority to start monitoring immediately.
                </p>

                <div className="pt-2 flex flex-col gap-3">
                  <label className="flex items-start gap-2.5 cursor-pointer text-caption text-text-primary">
                    <input
                      type="checkbox"
                      checked={fastTrackAccepted}
                      onChange={(e) => setFastTrackAccepted(e.target.checked)}
                      className="mt-0.5 rounded border-border text-accent focus:ring-accent"
                    />
                    <span>
                      I certify that I am the authorized owner or administrator for{' '}
                      <strong className="font-mono">{domain}</strong> and authorize automated security scanning.
                    </span>
                  </label>

                  <button
                    type="button"
                    disabled={!fastTrackAccepted || fastTrackLoading}
                    onClick={handleFastTrackVerify}
                    className="w-full sm:w-auto px-5 py-2.5 rounded-lg bg-accent hover:bg-accent-hover text-white font-semibold text-caption transition-colors flex items-center justify-center gap-2 shadow-sm disabled:opacity-50"
                  >
                    {fastTrackLoading ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        <span>Authorizing Domain...</span>
                      </>
                    ) : (
                      <>
                        <Zap className="w-4 h-4" />
                        <span>Authorize & Verify Domain Immediately</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-4">
                <button
                  type="button"
                  onClick={() => setCreatedAsset(null)}
                  className="text-caption text-text-tertiary hover:text-text-primary hover:underline"
                >
                  ← Choose a different domain
                </button>

                <button
                  type="button"
                  disabled={verifying}
                  onClick={handleCheckVerification}
                  className="w-full sm:w-auto px-6 py-2.5 rounded-lg bg-surface-raised border border-border hover:bg-surface-overlay text-text-primary font-semibold text-body transition-colors flex items-center justify-center gap-2 shadow-sm disabled:opacity-50"
                >
                  {verifying ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>Checking DNS Records...</span>
                    </>
                  ) : (
                    <>
                      <RefreshCw className="w-4 h-4" />
                      <span>Check DNS Records Now</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function OnboardingPage() {
  return (
    <Suspense
      fallback={
        <div className="py-16 flex flex-col items-center justify-center space-y-3">
          <Loader2 className="w-8 h-8 text-accent animate-spin" />
          <p className="text-caption text-text-secondary">Loading onboarding workflow...</p>
        </div>
      }
    >
      <OnboardingContent />
    </Suspense>
  );
}
