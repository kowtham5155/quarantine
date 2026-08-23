import type { Metadata, Viewport } from 'next';
import { headers } from 'next/headers';
import { GeistMono } from 'geist/font/mono';
import { GeistSans } from 'geist/font/sans';

import { ThemeProvider } from '@/components/shared/ThemeProvider';
import { Toaster } from '@/components/ui/sonner';
import { TooltipProvider } from '@/components/ui/tooltip';

import './globals.css';

export const metadata: Metadata = {
  title: {
    default: 'Quarantine — pre-install supply chain malware detection',
    template: '%s · Quarantine',
  },
  description:
    'Analyses the published tarball, not a CVE database, and returns a verdict before a package reaches a developer machine or CI runner.',
  applicationName: 'Quarantine',
  robots: { index: true, follow: true },
};

export const viewport: Viewport = {
  themeColor: '#09090b',
  colorScheme: 'dark light',
  width: 'device-width',
  initialScale: 1,
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Set by middleware.ts. next-themes injects an inline script to apply the
  // stored theme before paint; under a strict CSP it needs the request nonce.
  const nonce = (await headers()).get('x-nonce') ?? undefined;

  return (
    <html
      lang="en"
      className={`${GeistSans.variable} ${GeistMono.variable} dark`}
      suppressHydrationWarning
    >
      <body className="min-h-svh antialiased">
        <a
          href="#main"
          className="sr-only rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground focus:not-sr-only focus:absolute focus:top-3 focus:left-3 focus:z-50"
        >
          Skip to content
        </a>

        <ThemeProvider
          attribute="class"
          defaultTheme="dark"
          enableSystem={false}
          disableTransitionOnChange
          nonce={nonce}
        >
          <TooltipProvider delayDuration={200}>{children}</TooltipProvider>
          <Toaster position="bottom-right" closeButton richColors={false} />
        </ThemeProvider>
      </body>
    </html>
  );
}
