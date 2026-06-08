/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        base: 'rgb(var(--color-base) / <alpha-value>)',
        panel: 'rgb(var(--color-panel) / <alpha-value>)',
        'panel-2': 'rgb(var(--color-panel-2) / <alpha-value>)',
        'panel-3': 'rgb(var(--color-panel-3) / <alpha-value>)',
        accent: 'rgb(var(--color-accent) / <alpha-value>)',
        focus: 'rgb(var(--color-focus) / <alpha-value>)',
        line: 'rgb(var(--color-line) / <alpha-value>)',
      },
      borderRadius: {
        lg: '0.5rem',
        xl: '0.5rem',
        '2xl': '0.625rem',
      },
      boxShadow: {
        panel: '0 16px 46px rgb(0 0 0 / 0.24)',
        glow: '0 0 0 1px rgb(125 211 252 / 0.16), 0 18px 52px rgb(0 0 0 / 0.28)',
      },
      fontFamily: {
        sans: [
          'Aptos',
          'IBM Plex Sans',
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          'BlinkMacSystemFont',
          'Segoe UI',
          'sans-serif',
        ],
        mono: ['JetBrains Mono', 'SFMono-Regular', 'Cascadia Code', 'Menlo', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
};
