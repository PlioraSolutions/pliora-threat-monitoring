'use client';

import React, { useState, useEffect } from 'react';

interface CinematicBrandIntroProps {
  onComplete?: () => void;
  isFadingOut?: boolean;
}

export function CinematicBrandIntro({ onComplete, isFadingOut = false }: CinematicBrandIntroProps) {
  // Cinematic Timeline Choreography:
  // 0ms: Initial atmosphere emergence
  // 300ms: 'o-emerge' - Ō appears at center with subtle scale-up & glowing macron
  // 1300ms: 'o-hold' - Anticipation hold, Ō stands alone in the center
  // 1800ms: 'reveal' - PLI and RA glide in from opposite sides with motion blur (P L I   Ō   R A)
  // 2600ms: 'complete' - Settles smoothly into unified PLIŌRA wordmark, THREAT MONITOR lockup fades in
  const [stage, setStage] = useState<'darkness' | 'o-emerge' | 'o-hold' | 'reveal' | 'complete'>('darkness');
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');

  useEffect(() => {
    // Detect active theme from HTML attribute or localStorage
    const detectTheme = () => {
      const current = document.documentElement.getAttribute('data-theme');
      if (current === 'light' || current === 'dark') return current;
      try {
        const saved = localStorage.getItem('theme');
        if (saved === 'light' || saved === 'dark') return saved;
      } catch (e) {}
      return 'dark';
    };

    setTheme(detectTheme());

    const observer = new MutationObserver(() => {
      setTheme(detectTheme());
    });
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    const t1 = setTimeout(() => setStage('o-emerge'), 300);
    const t2 = setTimeout(() => setStage('o-hold'), 1300);
    const t3 = setTimeout(() => setStage('reveal'), 1800);
    const t4 = setTimeout(() => setStage('complete'), 2600);

    return () => {
      observer.disconnect();
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
    };
  }, []);

  const isLight = theme === 'light';
  const isOVisible = stage !== 'darkness';
  const areWingsVisible = stage === 'reveal' || stage === 'complete';
  const isComplete = stage === 'complete';

  // In Stage 1 & 2 (Ō alone), apply an optical -0.16em shift so Ō sits at the exact 50.00% screen center.
  // In Stage 3 & 4, smoothly ease to 0 so the entire PLIŌRA + THREAT MONITOR lockup sits perfectly centered.
  const lockupShift = isComplete || stage === 'reveal' ? 'translate-x-0' : '-translate-x-[0.16em]';

  return (
    <div
      className={`fixed inset-0 z-[100] flex items-center justify-center overflow-hidden select-none pointer-events-none transition-all duration-500 ease-out ${
        isLight ? 'bg-white text-slate-900' : 'bg-[#030508] text-white'
      } ${isFadingOut ? 'opacity-0 scale-105 filter blur-sm' : 'opacity-100 scale-100 filter blur-0'}`}
      aria-label="PLIŌRA Brand Experience"
    >
      {/* 1. Ambient Backlight Glow (Theme Adaptive) */}
      <div
        className={`absolute inset-0 pointer-events-none transition-opacity duration-1000 ease-out ${
          isOVisible ? 'opacity-100' : 'opacity-0'
        }`}
      >
        <div
          className="absolute inset-0 animate-ambient-pulse"
          style={{
            background: isLight
              ? 'radial-gradient(circle 600px at 50% 50%, rgba(53, 100, 216, 0.14) 0%, rgba(79, 70, 229, 0.04) 45%, transparent 75%)'
              : 'radial-gradient(circle 600px at 50% 50%, rgba(76, 126, 242, 0.18) 0%, rgba(30, 58, 138, 0.06) 45%, transparent 75%)',
          }}
        />
      </div>

      {/* 2. Soft Vignette for Depth */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background: isLight
            ? 'radial-gradient(ellipse at center, transparent 45%, rgba(241, 245, 249, 0.65) 100%)'
            : 'radial-gradient(ellipse at center, transparent 35%, rgba(3, 5, 8, 0.9) 100%)',
        }}
      />

      {/* 3. Horizontal Optical Flare Beam across the macron line */}
      <div
        className={`absolute w-full h-[1px] top-1/2 -translate-y-12 sm:-translate-y-16 pointer-events-none transition-all duration-1000 ease-out ${
          isOVisible ? 'opacity-40 scale-x-100' : 'opacity-0 scale-x-50'
        }`}
        style={{
          background: isLight
            ? 'radial-gradient(circle at 50% 50%, rgba(53, 100, 216, 0.5) 0%, rgba(59, 130, 246, 0.15) 30%, transparent 70%)'
            : 'radial-gradient(circle at 50% 50%, rgba(147, 197, 253, 0.75) 0%, rgba(59, 130, 246, 0.25) 25%, transparent 70%)',
        }}
      />

      {/* 4. Main Camera Stage with Ultra-Subtle 1.02x Depth Push-In */}
      <div className="relative z-10 flex flex-col items-center justify-center animate-cinematic-camera">
        {/* Unified Brand Lockup Container (PLIŌRA + THREAT MONITOR perfectly aligned together) */}
        <div
          className={`flex flex-col items-center justify-center transition-transform duration-1000 ease-[cubic-bezier(0.16,1,0.3,1)] ${lockupShift}`}
        >
          {/* Brand Typography Row */}
          <div className="relative inline-flex items-center justify-center font-sans text-5xl sm:text-7xl md:text-8xl font-bold tracking-[0.16em]">
            {/* Left Wing: P L I */}
            <div
              className={`inline-flex items-center select-none transition-all duration-1000 ease-[cubic-bezier(0.16,1,0.3,1)] ${
                areWingsVisible
                  ? 'opacity-100 translate-x-0 blur-0'
                  : 'opacity-0 -translate-x-14 blur-md pointer-events-none'
              }`}
            >
              <span className={isLight ? 'text-slate-900 drop-shadow-[0_2px_10px_rgba(0,0,0,0.06)]' : 'bg-gradient-to-b from-white via-[#F8FAFC] to-[#CBD5E1] bg-clip-text text-transparent drop-shadow-[0_0_24px_rgba(255,255,255,0.18)]'}>
                P
              </span>
              <span className={isLight ? 'text-slate-900 drop-shadow-[0_2px_10px_rgba(0,0,0,0.06)]' : 'bg-gradient-to-b from-white via-[#F8FAFC] to-[#CBD5E1] bg-clip-text text-transparent drop-shadow-[0_0_24px_rgba(255,255,255,0.18)]'}>
                L
              </span>
              <span className={isLight ? 'text-slate-900 drop-shadow-[0_2px_10px_rgba(0,0,0,0.06)]' : 'bg-gradient-to-b from-white via-[#F8FAFC] to-[#CBD5E1] bg-clip-text text-transparent drop-shadow-[0_0_24px_rgba(255,255,255,0.18)]'}>
                I
              </span>
            </div>

            {/* Center Anchor: Ō (Letter O + Absolute Floating Macron Bar) */}
            <div
              className={`relative inline-flex items-center justify-center select-none transition-all duration-1000 ease-[cubic-bezier(0.16,1,0.3,1)] ${
                isOVisible
                  ? 'opacity-100 scale-100 blur-0'
                  : 'opacity-0 scale-90 blur-lg pointer-events-none'
              }`}
            >
              {/* Architectural Glowing Macron Bar - Absolutely positioned above O so baseline is 100% unaffected */}
              <div
                className={`absolute bottom-[108%] left-1/2 -translate-x-1/2 h-[3px] sm:h-[4px] w-[0.68em] rounded-full transition-all duration-1000 ease-out animate-macron-glow ${
                  isLight
                    ? 'bg-gradient-to-r from-blue-600 via-blue-500 to-indigo-600 shadow-[0_0_12px_rgba(37,99,235,0.6),0_0_24px_rgba(59,130,246,0.35)]'
                    : 'bg-gradient-to-r from-blue-300 via-white to-blue-300 shadow-[0_0_14px_rgba(96,165,250,0.9),0_0_28px_rgba(59,130,246,0.6)]'
                } ${isOVisible ? 'opacity-100 scale-x-100' : 'opacity-0 scale-x-0'}`}
              />

              {/* Letter O - on the exact same vertical baseline and line-height as surrounding letters */}
              <span
                className={`leading-none select-none ${
                  isLight
                    ? 'text-slate-900 drop-shadow-[0_2px_10px_rgba(0,0,0,0.06)]'
                    : 'bg-gradient-to-b from-white via-[#F8FAFC] to-[#CBD5E1] bg-clip-text text-transparent drop-shadow-[0_0_24px_rgba(255,255,255,0.18)]'
                }`}
              >
                O
              </span>
            </div>

            {/* Right Wing: R A */}
            <div
              className={`inline-flex items-center select-none transition-all duration-1000 ease-[cubic-bezier(0.16,1,0.3,1)] ${
                areWingsVisible
                  ? 'opacity-100 translate-x-0 blur-0'
                  : 'opacity-0 translate-x-14 blur-md pointer-events-none'
              }`}
            >
              <span className={isLight ? 'text-slate-900 drop-shadow-[0_2px_10px_rgba(0,0,0,0.06)]' : 'bg-gradient-to-b from-white via-[#F8FAFC] to-[#CBD5E1] bg-clip-text text-transparent drop-shadow-[0_0_24px_rgba(255,255,255,0.18)]'}>
                R
              </span>
              <span className={isLight ? 'text-slate-900 drop-shadow-[0_2px_10px_rgba(0,0,0,0.06)]' : 'bg-gradient-to-b from-white via-[#F8FAFC] to-[#CBD5E1] bg-clip-text text-transparent drop-shadow-[0_0_24px_rgba(255,255,255,0.18)]'}>
                A
              </span>
            </div>
          </div>

          {/* 5. Minimalist Brand Descriptor - Perfectly Centered Directly Underneath PLIŌRA */}
          <div
            className={`w-full mt-7 transition-all duration-1000 ease-out flex items-center justify-center gap-3.5 ${
              isComplete
                ? 'opacity-100 translate-y-0 blur-0'
                : 'opacity-0 translate-y-3 blur-xs pointer-events-none'
            }`}
          >
            <div
              className={`w-8 sm:w-12 h-[1px] ${
                isLight
                  ? 'bg-gradient-to-r from-transparent to-slate-400/60'
                  : 'bg-gradient-to-r from-transparent to-blue-400/50'
              }`}
            />
            <span
              className={`text-[11px] sm:text-xs font-semibold tracking-[0.45em] uppercase font-mono ${
                isLight ? 'text-slate-600' : 'text-blue-200/85'
              }`}
            >
              THREAT MONITOR
            </span>
            <div
              className={`w-8 sm:w-12 h-[1px] ${
                isLight
                  ? 'bg-gradient-to-l from-transparent to-slate-400/60'
                  : 'bg-gradient-to-l from-transparent to-blue-400/50'
              }`}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
