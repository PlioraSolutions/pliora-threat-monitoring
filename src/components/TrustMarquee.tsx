'use client';

import React from 'react';

const DATA_SOURCES = [
  { name: 'Certificate Transparency Logs', category: 'RFC 6962' },
  { name: 'Passive DNS Aggregators', category: 'Global Recursive' },
  { name: 'WHOIS & RDAP Registries', category: 'ICANN / RIRs' },
  { name: 'NVD / CVE Vulnerability Feeds', category: 'NIST Standards' },
  { name: 'EPSS Exploit Prediction', category: 'FIRST.org' },
  { name: 'BGP & ASN Routing Tables', category: 'Internet Core' },
  { name: 'TLS & Security Header Observatories', category: 'W3C / IETF' },
];

export function TrustMarquee() {
  return (
    <section className="border-b border-border bg-bg-raised py-6 overflow-hidden">
      <div className="max-w-[1200px] mx-auto px-6 mb-3">
        <div className="text-[11px] font-mono uppercase tracking-wider text-text-tertiary">
          Passive intelligence sources & telemetry feeds
        </div>
      </div>

      <div className="relative w-full overflow-hidden [mask-image:linear-gradient(to_right,transparent,black_10%,black_90%,transparent)]">
        <div className="animate-marquee flex items-center space-x-10">
          {/* First set */}
          {DATA_SOURCES.map((source, idx) => (
            <div
              key={`src-1-${idx}`}
              className="flex items-center space-x-3 text-text-secondary opacity-60 hover:opacity-100 transition-opacity duration-hover cursor-default select-none whitespace-nowrap"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-accent/60"></span>
              <span className="text-[14px] font-medium tracking-tight text-text-primary">
                {source.name}
              </span>
              <span className="text-[11px] font-mono px-1.5 py-0.5 rounded border border-border text-text-tertiary">
                {source.category}
              </span>
            </div>
          ))}

          {/* Duplicated set for seamless 40s loop */}
          {DATA_SOURCES.map((source, idx) => (
            <div
              key={`src-2-${idx}`}
              className="flex items-center space-x-3 text-text-secondary opacity-60 hover:opacity-100 transition-opacity duration-hover cursor-default select-none whitespace-nowrap"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-accent/60"></span>
              <span className="text-[14px] font-medium tracking-tight text-text-primary">
                {source.name}
              </span>
              <span className="text-[11px] font-mono px-1.5 py-0.5 rounded border border-border text-text-tertiary">
                {source.category}
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
