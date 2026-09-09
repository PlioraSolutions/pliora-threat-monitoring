'use client';

import React from 'react';
import { Menu, LogOut, Building, Shield } from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { ThemeToggle } from './ThemeToggle';

interface HeaderProps {
  onOpenSidebar: () => void;
}

export function Header({ onOpenSidebar }: HeaderProps) {
  const { user, organization, role, logout } = useAuth();

  let roleBadgeClass = 'bg-surface-raised text-text-secondary border-border';
  if (role === 'OWNER') {
    roleBadgeClass = 'bg-accent/10 text-accent border-accent/30';
  } else if (role === 'ADMIN') {
    roleBadgeClass = 'bg-sev-high/10 text-sev-high border-sev-high/30';
  } else if (role === 'VIEWER') {
    roleBadgeClass = 'bg-surface-overlay text-text-tertiary border-border';
  }

  return (
    <header className="h-16 bg-surface border-b border-border px-6 flex items-center justify-between sticky top-0 z-20">
      {/* Left: Mobile menu + Org Name */}
      <div className="flex items-center gap-3">
        <button
          onClick={onOpenSidebar}
          className="lg:hidden p-1.5 text-text-secondary hover:text-text-primary rounded-md hover:bg-surface-raised"
          aria-label="Open sidebar"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-2.5">
          <div className="p-1.5 bg-surface-raised rounded-md text-text-tertiary">
            <Building className="w-4 h-4" />
          </div>
          <div>
            <div className="text-body font-bold text-text-primary flex items-center gap-2">
              <span>{organization?.name || 'My Organization'}</span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-surface-overlay text-text-tertiary border border-border">
                {organization?.plan || 'STARTER'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Right: User Role + ThemeToggle + Logout */}
      <div className="flex items-center gap-3">
        {/* Role Badge */}
        {role && (
          <span
            className={`hidden sm:inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-caption font-semibold border ${roleBadgeClass}`}
            title={`Your organization role is ${role}`}
          >
            <Shield className="w-3 h-3" />
            <span>{role}</span>
          </span>
        )}

        {/* User Info */}
        <div className="hidden md:block text-right">
          <div className="text-caption font-medium text-text-primary leading-tight">
            {user?.name || user?.email || 'Authenticated User'}
          </div>
          <div className="text-[11px] text-text-tertiary leading-tight">
            {user?.email}
          </div>
        </div>

        <div className="h-6 w-px bg-border mx-1 hidden sm:block" />

        <ThemeToggle />

        {/* Logout Button */}
        <button
          onClick={() => logout()}
          title="Log out"
          className="p-2 text-text-secondary hover:text-sev-critical hover:bg-sev-critical/10 rounded-md transition-colors"
        >
          <LogOut className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
}
