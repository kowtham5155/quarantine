'use client';

import Link from 'next/link';
import { AlertOctagon } from 'lucide-react';
import type { ReactNode } from 'react';

import { Button } from '@/components/ui/button';

export interface RouteErrorProps {
  title: string;
  description?: ReactNode;
  /** Next hands this to every error boundary; only `digest` is ever shown. */
  error: Error & { digest?: string };
  reset: () => void;
  /** Somewhere useful to go when retrying is not going to help. */
  secondary?: { href: string; label: string };
}

/**
 * The shared body of every `error.tsx` in the application.
 *
 * The error object itself is never rendered — a boundary is a client component
 * and its message can carry internals (CLAUDE.md rule 5). The digest is the
 * correlation handle: it appears in the server log next to the real cause.
 */
export function RouteError({
  title,
  description = 'The failure has been recorded. Retrying often resolves it.',
  error,
  reset,
  secondary = { href: '/dashboard', label: 'Go to the dashboard' },
}: RouteErrorProps) {
  return (
    <div className="flex min-h-[50svh] flex-col items-center justify-center gap-6 text-center">
      <div className="flex size-12 items-center justify-center rounded-full bg-verdict-suspicious-surface text-verdict-suspicious-accent">
        <AlertOctagon aria-hidden="true" className="size-6" />
      </div>
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        <p className="max-w-md text-sm text-balance text-muted-foreground">{description}</p>
        {error.digest ? (
          <p className="font-mono text-xs text-muted-foreground">Reference: {error.digest}</p>
        ) : null}
      </div>
      <div className="flex flex-wrap items-center justify-center gap-2">
        <Button onClick={reset}>Try again</Button>
        <Button asChild variant="outline">
          <Link href={secondary.href}>{secondary.label}</Link>
        </Button>
      </div>
    </div>
  );
}
