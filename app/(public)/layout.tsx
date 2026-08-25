import Link from 'next/link';
import type { ReactNode } from 'react';
import { ShieldCheck } from 'lucide-react';

import { Button } from '@/components/ui/button';

const NAV = [
  { href: '/how-it-works', label: 'How it works' },
  { href: '/detections', label: 'Detections' },
  { href: '/research', label: 'Research' },
  { href: '/docs', label: 'Docs' },
  { href: '/security', label: 'Security' },
] as const;

/**
 * Shell for everything a signed-out visitor can reach.
 *
 * Kept separate from AppShell: the marketing and reference pages have no
 * organisation, no session and no tenant data, and giving them the application
 * sidebar would imply otherwise.
 */
export default function PublicLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-svh flex-col">
      <header className="sticky top-0 z-40 border-b border-border bg-background/85 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center gap-3 px-4 sm:px-6">
          <Link href="/" className="flex items-center gap-2 font-semibold tracking-tight">
            <ShieldCheck aria-hidden="true" className="size-5 text-primary" />
            Quarantine
          </Link>

          <nav
            aria-label="Primary"
            className="ml-6 hidden gap-5 text-sm text-muted-foreground md:flex"
          >
            {NAV.map((item) => (
              <Link key={item.href} href={item.href} className="hover:text-foreground">
                {item.label}
              </Link>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-2">
            <Button asChild variant="ghost" size="sm">
              <Link href="/login">Sign in</Link>
            </Button>
            <Button asChild size="sm">
              <Link href="/scan">Scan a package</Link>
            </Button>
          </div>
        </div>
      </header>

      <main id="main" className="mx-auto w-full max-w-6xl flex-1 px-4 py-12 sm:px-6 sm:py-16">
        {children}
      </main>

      <footer className="border-t border-border">
        <div className="mx-auto flex max-w-6xl flex-col gap-3 px-4 py-6 text-xs text-muted-foreground sm:flex-row sm:items-center sm:px-6">
          <p>Static analysis only. Package contents are never executed.</p>
          <nav aria-label="Footer" className="flex flex-wrap gap-4 sm:ml-auto">
            <Link href="/security" className="hover:text-foreground">
              Security
            </Link>
            <Link href="/docs" className="hover:text-foreground">
              Docs
            </Link>
            <Link href="/legal/terms" className="hover:text-foreground">
              Terms
            </Link>
            <Link href="/legal/privacy" className="hover:text-foreground">
              Privacy
            </Link>
          </nav>
        </div>
      </footer>
    </div>
  );
}
