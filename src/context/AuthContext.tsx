'use client';

import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { api, ApiError } from '@/lib/client/api';

export type UserRole = 'OWNER' | 'ADMIN' | 'MEMBER' | 'VIEWER';

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  globalRole: string;
}

export interface AuthOrganization {
  id: string;
  name: string;
  slug: string;
  plan: string;
  accountType?: string;
  scanQuotas?: {
    maxMonitoredDomains: number;
    dailyScanLimit: number;
    concurrentScans: number;
  };
  settings?: Record<string, any>;
}

interface AuthContextType {
  user: AuthUser | null;
  organization: AuthOrganization | null;
  role: UserRole | null;
  loading: boolean;
  error: string | null;
  login: (email: string, password: string, options?: { skipRedirect?: boolean }) => Promise<void>;
  register: (name: string, organizationName: string, email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();

  const [user, setUser] = useState<AuthUser | null>(null);
  const [organization, setOrganization] = useState<AuthOrganization | null>(null);
  const [role, setRole] = useState<UserRole | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchSession = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.get('/api/auth/me');
      if (data?.user && data?.organization) {
        setUser(data.user);
        setOrganization(data.organization);
        setRole(data.user.role || 'MEMBER');
      } else {
        setUser(null);
        setOrganization(null);
        setRole(null);
      }
    } catch (err: any) {
      setUser(null);
      setOrganization(null);
      setRole(null);
      if (err instanceof ApiError && err.status === 401) {
        // Expected when unauthenticated
      } else {
        setError(err.message || 'Failed to authenticate');
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSession();
  }, [fetchSession]);

  const login = async (email: string, password: string, options?: { skipRedirect?: boolean }) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.post('/api/auth/login', { email, password });
      if (data?.user && data?.organization) {
        setUser(data.user);
        setOrganization(data.organization);
        setRole(data.user.role || 'MEMBER');
      } else {
        await fetchSession();
      }
      if (!options?.skipRedirect) {
        router.push('/dashboard');
      }
    } catch (err: any) {
      setError(err.message || 'Login failed');
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const register = async (
    nameOrOrg: string,
    organizationName?: string,
    email?: string,
    password?: string
  ) => {
    setLoading(true);
    setError(null);
    try {
      let finalName = nameOrOrg;
      let finalOrg = organizationName || nameOrOrg;
      let finalEmail = email;
      let finalPassword = password;

      // Handle 3 arguments overload (orgName, email, password)
      if (email === undefined && password === undefined && organizationName !== undefined) {
        finalName = nameOrOrg.split('@')[0] || 'Admin User';
        finalOrg = nameOrOrg;
        finalEmail = organizationName;
        finalPassword = email;
      }

      if (!finalName || finalName.length < 2) {
        finalName = finalEmail?.split('@')[0] || 'Admin User';
      }

      const data = await api.post('/api/auth/register', {
        name: finalName,
        organizationName: finalOrg,
        email: finalEmail,
        password: finalPassword,
      });
      if (data?.user && data?.organization) {
        setUser(data.user);
        setOrganization(data.organization);
        setRole(data.user.role || 'OWNER');
      } else {
        await fetchSession();
      }
      router.push('/onboarding');
    } catch (err: any) {
      setError(err.message || 'Registration failed');
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try {
      await api.post('/api/auth/logout');
    } catch (err) {
      console.warn('Logout request failed:', err);
    } finally {
      setUser(null);
      setOrganization(null);
      setRole(null);
      router.push('/login');
    }
  };

  const value: AuthContextType = {
    user,
    organization,
    role,
    loading,
    error,
    login,
    register,
    logout,
    refresh: fetchSession,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
