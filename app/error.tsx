'use client';

import { useEffect } from 'react';
import Link from 'next/link';
import { AlertOctagon } from 'lucide-react';

import { Button } from '@/components/ui/button';

/**
 * Route-level error boundary.
 *
 * Only `digest` is shown. The message on an Error surfaced to the client is not
 * guaranteed to be one of ours, and CLAUDE.md rule 5 is explicit: no raw error
 * text, no stack traces. The digest is the handle for finding the real error in
 * the server logs.
 */
export default function ErrorBoundary({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Next has already logged this server-side with the matching digest.
  }, [error]);

  return (
    <div className="flex min-h-[60svh] flex-col items-center justify-center gap-6 px-4 text-center">
      <div className="flex size-12 items-center justify-center rounded-full bg-verdict-suspicious-surface text-verdict-suspicious-accent">
        <AlertOctagon aria-hidden="true" className="size-6" />
      </div>
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">Something went wrong</h1>
        <p className="max-w-md text-sm text-balance text-muted-foreground">
          This page failed to load. The failure has been recorded — retrying often resolves it.
        </p>
        {error.digest ? (
          <p className="font-mono text-xs text-muted-foreground">Reference: {error.digest}</p>
        ) : null}
      </div>
      <div className="flex flex-wrap items-center justify-center gap-2">
        <Button onClick={reset}>Try again</Button>
        <Button asChild variant="outline">
          <Link href="/dashboard">Back to dashboard</Link>
        </Button>
      </div>
    </div>
  );
}
