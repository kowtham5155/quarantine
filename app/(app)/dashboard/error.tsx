'use client';

import Link from 'next/link';
import { AlertOctagon } from 'lucide-react';

import { Button } from '@/components/ui/button';

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="flex min-h-[50svh] flex-col items-center justify-center gap-6 text-center">
      <div className="flex size-12 items-center justify-center rounded-full bg-verdict-suspicious-surface text-verdict-suspicious-accent">
        <AlertOctagon aria-hidden="true" className="size-6" />
      </div>
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">The dashboard failed to load</h1>
        <p className="max-w-md text-sm text-balance text-muted-foreground">
          The failure has been recorded. Retrying often resolves it.
        </p>
        {error.digest ? (
          <p className="font-mono text-xs text-muted-foreground">Reference: {error.digest}</p>
        ) : null}
      </div>
      <div className="flex flex-wrap items-center justify-center gap-2">
        <Button onClick={reset}>Try again</Button>
        <Button asChild variant="outline">
          <Link href="/scan">Run a scan instead</Link>
        </Button>
      </div>
    </div>
  );
}
