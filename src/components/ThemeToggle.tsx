'use client';

import React, { useEffect, useState } from 'react';
import { Sun, Moon } from 'lucide-react';

export function ThemeToggle({ iconOnly = false }: { iconOnly?: boolean } = {}) {
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');

  useEffect(() => {
    const current = document.documentElement.getAttribute('data-theme') as 'dark' | 'light';
    if (current) {
      setTheme(current);
    }
  }, []);

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
    try {
      localStorage.setItem('theme', nextTheme);
    } catch (e) {}
  };

  if (iconOnly) {
    return (
      <button
        onClick={toggleTheme}
        aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
        title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
        className="group w-8 h-8 rounded-full flex items-center justify-center text-text-secondary hover:text-text-primary hover:bg-black/[0.04] dark:hover:bg-white/[0.07] transition-all duration-200 focus:outline-none"
      >
        {theme === 'dark' ? (
          <Sun className="h-4 w-4 transition-transform duration-300 ease-out group-hover:rotate-45 group-hover:scale-110" />
        ) : (
          <Moon className="h-4 w-4 transition-transform duration-300 ease-out group-hover:-rotate-12 group-hover:scale-110" />
        )}
      </button>
    );
  }

  return (
    <button
      onClick={toggleTheme}
      aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
      className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-btn border border-border-strong text-caption text-text-secondary hover:text-text-primary hover:border-text-secondary transition-colors duration-hover"
    >
      {theme === 'dark' ? (
        <>
          <Sun className="h-3.5 w-3.5" />
          <span>Light theme</span>
        </>
      ) : (
        <>
          <Moon className="h-3.5 w-3.5" />
          <span>Dark theme</span>
        </>
      )}
    </button>
  );
}
