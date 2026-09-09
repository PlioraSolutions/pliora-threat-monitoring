/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['var(--font-sans)', 'sans-serif'],
        mono: ['var(--font-mono)', 'monospace'],
      },
      colors: {
        bg: {
          DEFAULT: 'var(--bg)',
          raised: 'var(--bg-raised)',
        },
        surface: {
          DEFAULT: 'var(--surface)',
          raised: 'var(--surface-raised)',
          overlay: 'var(--surface-overlay)',
        },
        border: {
          DEFAULT: 'var(--border)',
          strong: 'var(--border-strong)',
        },
        text: {
          primary: 'var(--text-primary)',
          secondary: 'var(--text-secondary)',
          tertiary: 'var(--text-tertiary)',
        },
        accent: {
          DEFAULT: 'var(--accent)',
          hover: 'var(--accent-hover)',
          muted: 'var(--accent-muted)',
        },
        sev: {
          critical: 'var(--sev-critical)',
          'critical-bg': 'var(--sev-critical-bg)',
          high: 'var(--sev-high)',
          'high-bg': 'var(--sev-high-bg)',
          medium: 'var(--sev-medium)',
          'medium-bg': 'var(--sev-medium-bg)',
          low: 'var(--sev-low)',
          'low-bg': 'var(--sev-low-bg)',
          info: 'var(--sev-info)',
          'info-bg': 'var(--sev-info-bg)',
        },
        node: {
          idle: 'var(--node-idle)',
          line: 'var(--node-line)',
        },
        mono: {
          bg: 'var(--mono-bg)',
          border: 'var(--mono-border)',
        },
        success: 'var(--success)',
        danger: 'var(--danger)',
      },
      fontSize: {
        display: ['40px', { lineHeight: '46px', fontWeight: '600' }],
        h1: ['24px', { lineHeight: '32px', fontWeight: '600' }],
        h2: ['18px', { lineHeight: '26px', fontWeight: '600' }],
        body: ['14px', { lineHeight: '22px', fontWeight: '400' }],
        'body-sm': ['13px', { lineHeight: '20px', fontWeight: '400' }],
        caption: ['12px', { lineHeight: '16px', fontWeight: '500' }],
        mono: ['13px', { lineHeight: '20px', fontWeight: '400' }],
      },
      borderRadius: {
        card: '8px',
        input: '8px',
        badge: '6px',
        btn: '6px',
        evidence: '4px',
      },
      transitionDuration: {
        hover: '120ms',
      },
    },
  },
  plugins: [],
};
