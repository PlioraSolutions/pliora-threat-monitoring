'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Shield,
  Activity,
  Globe,
  AlertTriangle,
  Layers,
  PlayCircle,
  Bell,
  Settings,
  PlusCircle,
  X,
  Users,
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';

interface SidebarProps {
  isOpen: boolean;
  onClose: () => void;
}

export function Sidebar({ isOpen, onClose }: SidebarProps) {
  const pathname = usePathname();
  const { organization } = useAuth();
  const isAgency = organization?.accountType === 'AGENCY';

  const navItems = [
    { name: 'Dashboard', href: '/dashboard', icon: Activity },
    { name: 'Asset Inventory', href: '/assets', icon: Globe },
    { name: 'Findings & Triage', href: '/findings', icon: AlertTriangle },
    { name: 'Brand & Threats', href: '/threats', icon: Layers },
    { name: 'Scan History', href: '/scans', icon: PlayCircle },
    { name: 'Alert History', href: '/alerts', icon: Bell },
    ...(isAgency ? [{ name: 'Agency Clients', href: '/agency/clients', icon: Users }] : []),
    { name: 'Settings & Team', href: '/settings', icon: Settings },
  ];

  return (
    <>
      {/* Mobile backdrop */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-30 lg:hidden"
          onClick={onClose}
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={`fixed top-0 bottom-0 left-0 z-40 w-64 bg-surface border-r border-border flex flex-col transition-transform duration-200 lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand Header */}
        <div className="h-16 px-6 border-b border-border flex items-center justify-between">
          <Link href="/dashboard" className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-accent flex items-center justify-center text-white font-bold shadow-md">
              P
            </div>
            <div>
              <span className="font-bold tracking-tight text-text-primary text-base">
                PLIŌRA
              </span>
              <span className="ml-1.5 text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-surface-overlay text-text-secondary border border-border">
                Threat Monitor
              </span>
            </div>
          </Link>

          <button
            onClick={onClose}
            className="lg:hidden p-1 text-text-tertiary hover:text-text-primary rounded-md"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Action Button: Add Domain / Onboarding */}
        <div className="p-4">
          <Link
            href="/onboarding"
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-accent hover:bg-accent-hover text-white text-body font-medium transition-colors shadow-sm"
          >
            <PlusCircle className="w-4 h-4" />
            <span>Add & Verify Domain</span>
          </Link>
        </div>

        {/* Navigation Links */}
        <nav className="flex-1 px-3 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive =
              pathname === item.href || (item.href !== '/dashboard' && pathname?.startsWith(item.href));

            return (
              <Link
                key={item.name}
                href={item.href}
                onClick={onClose}
                className={`flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-body font-medium transition-colors ${
                  isActive
                    ? 'bg-surface-raised text-accent font-semibold border-l-2 border-accent'
                    : 'text-text-secondary hover:text-text-primary hover:bg-surface-raised/60'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-accent' : 'text-text-tertiary'}`} />
                <span>{item.name}</span>
              </Link>
            );
          })}
        </nav>

        {/* Footer info */}
        <div className="p-4 border-t border-border text-[11px] text-text-tertiary space-y-1">
          <div>PLIŌRA MVP v0.1.0</div>
          <div className="flex items-center gap-1.5 text-sev-low">
            <span className="w-1.5 h-1.5 rounded-full bg-sev-low animate-pulse" />
            <span>Real-time Sentinel Active</span>
          </div>
        </div>
      </aside>
    </>
  );
}
