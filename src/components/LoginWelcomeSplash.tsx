'use client';

import React, { useState, useEffect } from 'react';
import { ShieldCheck, Sparkles } from 'lucide-react';

interface LoginWelcomeSplashProps {
  organizationName?: string;
}

export function LoginWelcomeSplash({ organizationName }: LoginWelcomeSplashProps) {
  const [currentStep, setCurrentStep] = useState(0);

  const steps = [
    'Verifying cryptographic session...',
    'Loading attack surface monitors...',
    'Preparing your security dashboard...',
  ];

  useEffect(() => {
    const timer1 = setTimeout(() => setCurrentStep(1), 700);
    const timer2 = setTimeout(() => setCurrentStep(2), 1500);
    return () => {
      clearTimeout(timer1);
      clearTimeout(timer2);
    };
  }, []);

  return (
    <div className="w-full max-w-md mx-auto flex flex-col items-center justify-center py-10 px-6 text-center animate-in fade-in duration-500">
      {/* 1. Small uppercase text upper: "WELCOME TO" */}
      <div className="flex items-center gap-2 mb-6">
        <Sparkles className="w-3.5 h-3.5 text-accent animate-pulse" />
        <span className="text-[11px] font-bold tracking-[0.35em] text-accent uppercase drop-shadow-sm">
          WELCOME TO
        </span>
        <Sparkles className="w-3.5 h-3.5 text-accent animate-pulse" />
      </div>

      {/* 2. Glowing Animated "Ō" Centerpiece */}
      <div className="relative flex items-center justify-center my-4">
        {/* Outer expanding radar ring */}
        <div className="absolute w-32 h-32 rounded-full border border-accent/30 animate-ping opacity-30" />
        
        {/* Middle ambient glow ring */}
        <div className="absolute w-28 h-28 rounded-full bg-accent/15 blur-xl animate-pulse" />

        {/* Inner glowing orb with border */}
        <div className="relative w-24 h-24 rounded-2xl bg-gradient-to-br from-surface-raised via-surface to-surface-overlay border-2 border-accent flex items-center justify-center shadow-[0_0_40px_rgba(76,126,242,0.4)]">
          {/* Decorative corner markers */}
          <div className="absolute top-1 left-1 w-2 h-2 border-t-2 border-l-2 border-accent/70" />
          <div className="absolute bottom-1 right-1 w-2 h-2 border-b-2 border-r-2 border-accent/70" />

          {/* The animated "Ō" symbol */}
          <div className="relative flex flex-col items-center justify-center">
            {/* Macron bar with glowing shimmer */}
            <div className="w-9 h-1.5 bg-accent rounded-full mb-1 shadow-[0_0_12px_var(--accent)] animate-pulse" />
            {/* The letter O */}
            <span className="text-4xl font-extrabold text-text-primary tracking-tight font-mono select-none drop-shadow-md">
              O
            </span>
          </div>
        </div>
      </div>

      {/* 3. Full Brand Text: "PLIŌRA" */}
      <div className="mt-6 flex items-baseline justify-center gap-0.5">
        <span className="text-3xl font-black tracking-widest text-text-primary font-sans">
          PLI
        </span>
        <span className="text-3xl font-black tracking-widest text-accent font-sans drop-shadow-[0_0_15px_rgba(76,126,242,0.6)]">
          Ō
        </span>
        <span className="text-3xl font-black tracking-widest text-text-primary font-sans">
          RA
        </span>
      </div>

      {/* Subtitle / Org badge */}
      <div className="mt-2 text-caption text-text-secondary flex items-center gap-1.5">
        <ShieldCheck className="w-4 h-4 text-accent" />
        <span>Threat Monitor & Attack Surface Management</span>
      </div>

      {/* 4. Animated progress shimmer bar & status text */}
      <div className="w-full max-w-xs mt-8 space-y-2">
        <div className="h-1.5 w-full bg-surface-raised border border-border rounded-full overflow-hidden relative">
          <div className="h-full bg-gradient-to-r from-accent via-accent-hover to-accent rounded-full animate-[progress_1.8s_ease-in-out_infinite] w-3/4 shadow-[0_0_10px_var(--accent)]" />
        </div>
        <p className="text-[12px] text-text-tertiary font-mono animate-pulse min-h-[18px]">
          {steps[currentStep]}
        </p>
      </div>
    </div>
  );
}
