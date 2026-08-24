'use client';

import { useEffect } from 'react';
import Link from 'next/link';
import { AlertTriangle } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

export default function OnboardingError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Logged server-side against the same digest; the message is never shown.
  }, [error]);

  return (
    <Card>
      <CardHeader className="gap-2">
        <div className="flex items-center gap-2">
          <AlertTriangle aria-hidden="true" className="size-5 text-destructive" />
          <CardTitle>Setup could not continue</CardTitle>
        </div>
        <CardDescription>
          Nothing was lost. Try the step again, or start over from the beginning.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error.digest ? (
          <p className="font-mono text-xs text-muted-foreground">Reference: {error.digest}</p>
        ) : null}
        <div className="flex gap-2">
          <Button onClick={reset}>Try again</Button>
          <Button asChild variant="outline">
            <Link href="/onboarding">Start over</Link>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
