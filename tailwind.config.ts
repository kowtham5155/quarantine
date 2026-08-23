import type { Config } from 'tailwindcss';

/**
 * Tailwind v4 reads the design tokens from `app/globals.css` (`@theme inline`).
 * This file is wired in via `@config` and carries the things that are still
 * expressed as configuration rather than CSS: the source globs Tailwind scans
 * for class names, and shared keyframes used by loading/skeleton states.
 */
const config: Config = {
  content: [
    './app/**/*.{ts,tsx,mdx}',
    './components/**/*.{ts,tsx}',
    './lib/**/*.{ts,tsx}',
    './middleware.ts',
  ],
  theme: {
    extend: {
      keyframes: {
        shimmer: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
      },
      animation: {
        shimmer: 'shimmer 1.6s ease-in-out infinite',
      },
    },
  },
  plugins: [],
};

export default config;
