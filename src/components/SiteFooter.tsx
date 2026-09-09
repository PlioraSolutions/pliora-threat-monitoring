'use client';

import React from 'react';
import Link from 'next/link';
import { ThemeToggle } from './ThemeToggle';

export function SiteFooter() {
  return (
    <footer className="border-t border-border bg-bg-raised text-text-secondary text-body-sm transition-colors">
      <div className="max-w-[1200px] mx-auto px-6 py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-12">
          {/* Col 1: Brand & Purpose */}
          <div className="space-y-3 md:col-span-1">
            <div className="flex items-center space-x-2">
              <span className="text-[17px] font-semibold text-text-primary tracking-tight">
                PLIŌRA
              </span>
              <span className="text-[11px] font-mono text-text-tertiary">
                Threat Monitor
              </span>
            </div>
            <p className="text-[13px] leading-relaxed text-text-secondary max-w-[28ch]">
              Continuous external attack-surface monitoring built for 1–20 domain businesses.
            </p>
            <div className="pt-2">
              <ThemeToggle />
            </div>
          </div>

          {/* Col 2: Product */}
          <div className="space-y-2.5">
            <div className="text-caption font-semibold text-text-primary uppercase tracking-wider">
              Product
            </div>
            <ul className="space-y-2">
              <li>
                <Link href="/#capabilities" className="hover:text-text-primary transition-colors duration-hover">
                  Capabilities (01–05)
                </Link>
              </li>
              <li>
                <Link href="/free-assessment" className="hover:text-text-primary transition-colors duration-hover">
                  Free assessment
                </Link>
              </li>
              <li>
                <Link href="/pricing" className="hover:text-text-primary transition-colors duration-hover">
                  Pricing & tiers
                </Link>
              </li>
              <li>
                <Link href="/faq" className="hover:text-text-primary transition-colors duration-hover">
                  Frequently asked questions
                </Link>
              </li>
              <li>
                <Link href="/dashboard" className="hover:text-text-primary transition-colors duration-hover">
                  Operations console
                </Link>
              </li>
            </ul>
          </div>

          {/* Col 3: Monitoring Pillars */}
          <div className="space-y-2.5">
            <div className="text-caption font-semibold text-text-primary uppercase tracking-wider">
              Monitoring Pillars
            </div>
            <ul className="space-y-2 text-[13px] font-mono text-text-secondary">
              <li>01. Asset Discovery</li>
              <li>02. Exposure Checks</li>
              <li>03. Threat & Brand Watch</li>
              <li>04. Deterministic Risk Engine</li>
              <li>05. Evidence-Grounded AI</li>
            </ul>
          </div>

          {/* Col 4: Trust & Policies */}
          <div className="space-y-2.5">
            <div className="text-caption font-semibold text-text-primary uppercase tracking-wider">
              Trust & Policies
            </div>
            <ul className="space-y-2 text-[13px]">
              <li>
                <Link href="/trust" className="hover:text-text-primary transition-colors">
                  Security & Trust Architecture
                </Link>
              </li>
              <li>
                <Link href="/terms" className="hover:text-text-primary transition-colors">
                  Terms of Service & AUP
                </Link>
              </li>
              <li>
                <a href="mailto:security@pliora.io" className="hover:text-text-primary transition-colors">
                  Report Security Vulnerability
                </a>
              </li>
            </ul>
            <p className="text-[12px] leading-relaxed text-text-tertiary pt-1">
              100% passive, read-only reconnaissance against verified public assets.
            </p>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="border-t border-border pt-6 flex flex-col sm:flex-row items-center justify-between text-caption text-text-tertiary gap-3">
          <div className="font-mono">
            © {new Date().getFullYear()} PLIŌRA Security Inc. All rights reserved.
          </div>
          <div className="flex items-center space-x-4">
            <Link href="/trust" className="hover:text-text-primary transition-colors">
              Trust Center
            </Link>
            <span>·</span>
            <Link href="/terms" className="hover:text-text-primary transition-colors">
              Terms & AUP
            </Link>
            <span>·</span>
            <span className="inline-flex items-center gap-1.5 font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-sev-low"></span>
              All systems operational
            </span>
            <span>·</span>
            <span className="font-mono">v1.0.0</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
