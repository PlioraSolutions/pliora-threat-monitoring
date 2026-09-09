'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Shield, ArrowRight, AlertCircle, Loader2 } from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { ThemeToggle } from '@/components/ThemeToggle';
import { CinematicBrandIntro } from '@/components/CinematicBrandIntro';

export default function LoginPage() {
  const router = useRouter();
  const { user, login, loading: authLoading } = useAuth();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [isRedirecting, setIsRedirecting] = useState(false);
  const [isFadingOut, setIsFadingOut] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!authLoading && user && !submitting && !isRedirecting) {
      router.push('/dashboard');
    }
  }, [user, authLoading, router, submitting, isRedirecting]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setError('Please enter both email and password.');
      return;
    }

    setError(null);
    setSubmitting(true);

    try {
      // 1. Trigger API authentication without instant navigation
      const loginPromise = login(email, password, { skipRedirect: true });

      // 2. Immediately switch to cinematic intro
      setIsRedirecting(true);

      // 3. Enforce 3.4s cinematic brand reveal choreography
      const cinematicTimer = new Promise((resolve) => setTimeout(resolve, 3400));

      await Promise.all([loginPromise, cinematicTimer]);

      // 4. Smooth cross-fade into dashboard
      setIsFadingOut(true);
      await new Promise((resolve) => setTimeout(resolve, 400));

      router.push('/dashboard');
    } catch (err: any) {
      setIsRedirecting(false);
      setIsFadingOut(false);
      setError(err.message || 'Invalid email or password. Please try again.');
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-bg flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      {/* Top right theme toggle */}
      {!isRedirecting && (
        <div className="absolute top-6 right-6">
          <ThemeToggle />
        </div>
      )}

      {isRedirecting && (
        <CinematicBrandIntro isFadingOut={isFadingOut} />
      )}

      {!isRedirecting && (
        <>
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
              Sign in to Threat Monitor
            </h1>
            <p className="text-caption text-text-secondary">
              Monitor your attack surface and protect customer-facing domains.
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
                    Email address
                  </label>
                  <input
                    type="email"
                    required
                    autoComplete="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="name@company.com"
                    className="w-full px-3.5 py-2.5 bg-surface-raised border border-border rounded-lg text-body text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none transition-colors"
                  />
                </div>

                <div>
                  <label className="block text-caption font-medium text-text-secondary mb-1">
                    Password
                  </label>
                  <input
                    type="password"
                    required
                    autoComplete="current-password"
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
                      <span>Signing in...</span>
                    </>
                  ) : (
                    <>
                      <span>Sign in</span>
                      <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </form>

              <div className="pt-4 border-t border-border text-center text-caption text-text-secondary">
                Don't have an account?{' '}
                <Link href="/register" className="text-accent font-semibold hover:underline">
                  Create organization account
                </Link>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
