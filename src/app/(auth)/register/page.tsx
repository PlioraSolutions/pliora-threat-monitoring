'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { ArrowRight, AlertCircle, Loader2, Building, CheckCircle2 } from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { ThemeToggle } from '@/components/ThemeToggle';

export default function RegisterPage() {
  const router = useRouter();
  const { user, register, loading: authLoading } = useAuth();

  const [name, setName] = useState('');
  const [orgName, setOrgName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!authLoading && user) {
      router.push('/dashboard');
    }
  }, [user, authLoading, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgName || !email || !password) {
      setError('Please fill in all required fields.');
      return;
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters long.');
      return;
    }

    setError(null);
    setSubmitting(true);

    try {
      const finalName = name.trim() || email.split('@')[0] || 'Security Lead';
      await register(finalName, orgName, email, password);
      // AuthContext redirects to /onboarding on success
    } catch (err: any) {
      setError(err.message || 'Registration failed. Please check your details.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-bg flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      {/* Top right theme toggle */}
      <div className="absolute top-6 right-6">
        <ThemeToggle />
      </div>

      <div className="sm:mx-auto sm:w-full sm:max-w-md text-center space-y-2">
        <Link href="/" className="inline-flex items-center gap-2.5">
          <div className="w-10 h-10 rounded-xl bg-accent flex items-center justify-center text-white font-bold text-xl shadow-lg">
            P
          </div>
          <span className="text-2xl font-bold tracking-tight text-text-primary">
            PLIŌRA
          </span>
        </Link>
        <h1 className="text-xl font-bold text-text-primary pt-2">
          Create your organization account
        </h1>
        <p className="text-caption text-text-secondary">
          Set up autonomous attack surface monitoring for your business in minutes.
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md px-4">
        <div className="bg-surface border border-border py-8 px-6 shadow-xl rounded-xl sm:px-10 space-y-6">
          {error && (
            <div className="p-3.5 bg-sev-critical/10 border border-sev-critical/30 rounded-lg flex items-start gap-2.5 text-sev-critical text-caption">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-caption font-medium text-text-secondary mb-1">
                Your full name
              </label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Jane Doe"
                className="w-full px-3.5 py-2.5 bg-surface-raised border border-border rounded-lg text-body text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none transition-colors"
              />
            </div>

            <div>
              <label className="block text-caption font-medium text-text-secondary mb-1">
                Organization or Company name
              </label>
              <input
                type="text"
                required
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                placeholder="Acme Security Inc."
                className="w-full px-3.5 py-2.5 bg-surface-raised border border-border rounded-lg text-body text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none transition-colors"
              />
            </div>

            <div>
              <label className="block text-caption font-medium text-text-secondary mb-1">
                Work email address
              </label>
              <input
                type="email"
                required
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="security@acme.com"
                className="w-full px-3.5 py-2.5 bg-surface-raised border border-border rounded-lg text-body text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none transition-colors"
              />
            </div>

            <div>
              <label className="block text-caption font-medium text-text-secondary mb-1">
                Password (min 8 characters)
              </label>
              <input
                type="password"
                required
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full px-3.5 py-2.5 bg-surface-raised border border-border rounded-lg text-body text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none transition-colors"
              />
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-accent hover:bg-accent-hover text-white font-medium text-body transition-colors shadow-sm disabled:opacity-50 mt-2"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Creating organization...</span>
                </>
              ) : (
                <>
                  <span>Create account & continue</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>

            <p className="text-[12px] text-text-tertiary text-center leading-relaxed pt-1">
              By creating an account, you agree to our{' '}
              <Link href="/terms" className="text-accent underline hover:text-accent-hover">
                Terms of Service
              </Link>{' '}
              and{' '}
              <Link href="/terms#acceptable-use" className="text-accent underline hover:text-accent-hover">
                Acceptable Use Policy
              </Link>
              .
            </p>
          </form>

          <div className="pt-4 border-t border-border text-center text-caption text-text-secondary">
            Already have an account?{' '}
            <Link href="/login" className="text-accent font-semibold hover:underline">
              Sign in
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
