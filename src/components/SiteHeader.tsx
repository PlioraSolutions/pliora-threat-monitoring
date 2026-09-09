'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Menu, X, ArrowRight } from 'lucide-react';
import { ThemeToggle } from './ThemeToggle';

export function SiteHeader() {
  const pathname = usePathname();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 12);
    };
    handleScroll();
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Close mobile menu on route change
  useEffect(() => {
    setMobileMenuOpen(false);
  }, [pathname]);

  const leftLinks = [
    { label: 'Capabilities', href: pathname === '/' ? '#capabilities' : '/#capabilities' },
    { label: 'Free assessment', href: '/free-assessment' },
  ];

  const rightLinks = [
    { label: 'Pricing', href: '/pricing' },
    { label: 'FAQ', href: '/faq' },
  ];

  return (
    <header className="sticky top-3 sm:top-4 z-50 w-full px-3 sm:px-6 pointer-events-none transition-all duration-200">
      {/* Floating Capsule Bar */}
      <div
        className={`pointer-events-auto max-w-[940px] w-full mx-auto h-[54px] sm:h-[58px] px-4 sm:px-6 rounded-full border transition-all duration-300 flex items-center justify-between ${
          isScrolled
            ? 'border-border bg-surface/95 backdrop-blur-2xl shadow-[0_12px_36px_-4px_rgba(0,0,0,0.12)]'
            : 'border-border bg-surface/90 backdrop-blur-xl shadow-[0_6px_28px_-4px_rgba(0,0,0,0.06)] hover:shadow-[0_10px_32px_-4px_rgba(0,0,0,0.1)]'
        }`}
      >
        {/* ========================================================= */}
        {/* DESKTOP 3-COLUMN GRID: Perfectly Centered Logo & Capsule  */}
        {/* ========================================================= */}
        <div className="hidden md:grid grid-cols-[1fr_auto_1fr] items-center w-full">
          {/* Column 1: Left Navigation Links (Equal spacing, right-balanced to center logo) */}
          <nav className="flex items-center justify-end gap-6 sm:gap-7 pr-6 lg:pr-7" aria-label="Capsule Navigation Left">
            {leftLinks.map((link) => {
              const isActive = link.href === pathname;
              return (
                <Link
                  key={link.label}
                  href={link.href}
                  className={`relative group text-[13.5px] font-medium transition-all duration-200 px-3 py-1.5 rounded-full hover:-translate-y-0.5 active:translate-y-0 whitespace-nowrap ${
                    isActive
                      ? 'text-text-primary font-semibold bg-surface-raised/70'
                      : 'text-text-secondary hover:text-text-primary hover:bg-black/[0.04] dark:hover:bg-white/[0.06]'
                  }`}
                >
                  <span className="relative z-10">{link.label}</span>
                  {/* Micro hover pip dot */}
                  <span
                    className="absolute bottom-1 left-1/2 -translate-x-1/2 w-1 h-1 rounded-full bg-text-primary opacity-0 group-hover:opacity-100 transition-all duration-200 scale-0 group-hover:scale-100"
                    aria-hidden="true"
                  />
                </Link>
              );
            })}
          </nav>

          {/* Column 2: Centered Logo / Wordmark */}
          <div className="flex items-center justify-center px-4">
            <Link
              href="/"
              className="flex items-center gap-2 group py-1 focus:outline-none select-none whitespace-nowrap"
              aria-label="PLIŌRA Threat Monitor Home"
            >
              <span className="text-[17.5px] lg:text-[18.5px] font-bold tracking-tight text-text-primary group-hover:text-accent transition-colors duration-200 leading-none">
                PLI<span className="inline-block transition-transform duration-300 ease-out group-hover:-translate-y-0.5">Ō</span>RA
              </span>
              <span className="text-[10px] font-mono text-text-tertiary font-medium tracking-wide uppercase leading-none transition-colors duration-200 group-hover:text-text-secondary">
                Threat Monitor
              </span>
            </Link>
          </div>

          {/* Column 3: Right Navigation Links, Theme Toggle & Pill CTA (Equal spacing, left-balanced to center logo) */}
          <div className="flex items-center justify-start gap-4 sm:gap-5 pl-6 lg:pl-7">
            <nav className="flex items-center gap-4 sm:gap-5" aria-label="Capsule Navigation Right">
              {rightLinks.map((link) => {
                const isActive = link.href === pathname;
                return (
                  <Link
                    key={link.label}
                    href={link.href}
                    className={`relative group text-[13.5px] font-medium transition-all duration-200 px-3 py-1.5 rounded-full hover:-translate-y-0.5 active:translate-y-0 whitespace-nowrap ${
                      isActive
                        ? 'text-text-primary font-semibold bg-surface-raised/70'
                        : 'text-text-secondary hover:text-text-primary hover:bg-black/[0.04] dark:hover:bg-white/[0.06]'
                    }`}
                  >
                    <span className="relative z-10">{link.label}</span>
                    {/* Micro hover pip dot */}
                    <span
                      className="absolute bottom-1 left-1/2 -translate-x-1/2 w-1 h-1 rounded-full bg-text-primary opacity-0 group-hover:opacity-100 transition-all duration-200 scale-0 group-hover:scale-100"
                      aria-hidden="true"
                    />
                  </Link>
                );
              })}
            </nav>

            {/* Subtle Divider */}
            <div className="h-4 w-[1px] bg-border mx-0.5" aria-hidden="true" />

            {/* Dark/Light Theme Toggle */}
            <ThemeToggle iconOnly={true} />

            {/* Primary Pill Button CTA with Smooth Lift, Shimmer & Sliding Arrow */}
            <Link
              href="/dashboard"
              className="relative group overflow-hidden inline-flex items-center gap-1.5 px-4 py-1.5 rounded-full bg-accent text-white text-[13px] font-medium hover:bg-accent-hover transition-all duration-200 shadow-[0_2px_10px_rgba(76,126,242,0.28)] hover:shadow-[0_4px_18px_rgba(76,126,242,0.45)] hover:-translate-y-0.5 active:translate-y-0 whitespace-nowrap ml-1"
            >
              {/* Shimmer light sweep */}
              <span
                className="absolute inset-0 -translate-x-full group-hover:translate-x-full transition-transform duration-700 bg-gradient-to-r from-transparent via-white/25 to-transparent pointer-events-none"
                aria-hidden="true"
              />
              <span>Open console</span>
              <ArrowRight className="w-3.5 h-3.5 transition-transform duration-200 group-hover:translate-x-1" />
            </Link>
          </div>
        </div>

        {/* ========================================================= */}
        {/* MOBILE VIEWPORT: Clean Balanced Capsule Controls          */}
        {/* ========================================================= */}
        <div className="flex md:hidden items-center justify-between w-full relative">
          {/* Mobile Menu Button (Left) */}
          <button
            type="button"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="w-8 h-8 rounded-full flex items-center justify-center text-text-secondary hover:text-text-primary hover:bg-black/[0.04] dark:hover:bg-white/[0.07] transition-all duration-150 focus:outline-none shrink-0"
            aria-label={mobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
            aria-expanded={mobileMenuOpen}
            aria-controls="mobile-capsule-dropdown"
          >
            {mobileMenuOpen ? <X size={18} /> : <Menu size={18} />}
          </button>

          {/* Centered Logo (Locked to 50% midpoint) */}
          <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 flex items-center justify-center pointer-events-auto">
            <Link
              href="/"
              className="flex items-center gap-1.5 group py-1 focus:outline-none select-none text-center whitespace-nowrap"
              aria-label="PLIŌRA Threat Monitor Home"
            >
              <span className="text-[16px] font-bold tracking-tight text-text-primary group-hover:text-accent transition-colors duration-150 leading-none">
                PLIŌRA
              </span>
              <span className="text-[9.5px] font-mono text-text-tertiary font-medium uppercase leading-none">
                Threat Monitor
              </span>
            </Link>
          </div>

          {/* Mobile Pill CTA (Right) */}
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-1 px-3 py-1 rounded-full bg-accent text-white text-[12px] font-medium hover:bg-accent-hover transition-all shadow-xs whitespace-nowrap shrink-0 active:scale-95"
          >
            <span>Console</span>
            <ArrowRight className="w-3 h-3" />
          </Link>
        </div>
      </div>

      {/* ========================================================= */}
      {/* MOBILE DROPDOWN: Matching Floating Glass Card             */}
      {/* ========================================================= */}
      {mobileMenuOpen && (
        <div
          id="mobile-capsule-dropdown"
          className="pointer-events-auto md:hidden max-w-[980px] w-full mx-auto mt-2 rounded-2xl border border-border bg-surface/95 backdrop-blur-2xl p-5 space-y-4 shadow-xl animate-in fade-in slide-in-from-top-2 duration-150"
        >
          <nav className="flex flex-col space-y-3" aria-label="Mobile Capsule Drawer">
            <Link
              href={pathname === '/' ? '#capabilities' : '/#capabilities'}
              onClick={() => setMobileMenuOpen(false)}
              className="text-[15px] font-medium text-text-secondary hover:text-text-primary transition-colors py-1 flex items-center justify-between"
            >
              <span>Capabilities</span>
              <span className="text-caption font-mono text-text-tertiary">01–05</span>
            </Link>
            <Link
              href="/free-assessment"
              onClick={() => setMobileMenuOpen(false)}
              className="text-[15px] font-medium text-text-secondary hover:text-text-primary transition-colors py-1"
            >
              Free assessment
            </Link>
            <Link
              href="/pricing"
              onClick={() => setMobileMenuOpen(false)}
              className="text-[15px] font-medium text-text-secondary hover:text-text-primary transition-colors py-1"
            >
              Pricing
            </Link>
            <Link
              href="/faq"
              onClick={() => setMobileMenuOpen(false)}
              className="text-[15px] font-medium text-text-secondary hover:text-text-primary transition-colors py-1"
            >
              Frequently asked questions
            </Link>

            <div className="pt-3 border-t border-border flex items-center justify-between">
              <span className="text-[13px] font-mono text-text-secondary">Theme appearance</span>
              <ThemeToggle />
            </div>

            <div className="pt-2">
              <Link
                href="/dashboard"
                onClick={() => setMobileMenuOpen(false)}
                className="w-full py-2.5 px-4 rounded-full bg-accent text-white text-[14px] font-medium hover:bg-accent-hover transition-colors duration-hover flex items-center justify-center gap-2 shadow-sm"
              >
                <span>Open console</span>
                <ArrowRight size={15} />
              </Link>
            </div>
          </nav>
        </div>
      )}
    </header>
  );
}

