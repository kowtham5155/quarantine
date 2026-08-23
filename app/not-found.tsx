import Link from 'next/link';
import { FileQuestion } from 'lucide-react';

import { Button } from '@/components/ui/button';

export default function NotFound() {
  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-6 px-4 text-center">
      <div className="flex size-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
        <FileQuestion aria-hidden="true" className="size-6" />
      </div>
      <div className="space-y-2">
        <p className="font-mono text-xs tracking-widest text-muted-foreground uppercase">404</p>
        <h1 className="text-2xl font-semibold tracking-tight">Page not found</h1>
        <p className="max-w-md text-sm text-balance text-muted-foreground">
          The page you were looking for does not exist. If you followed a link to a package report,
          the analysis may have been removed or belongs to another organisation.
        </p>
      </div>
      <div className="flex flex-wrap items-center justify-center gap-2">
        <Button asChild>
          <Link href="/dashboard">Go to dashboard</Link>
        </Button>
        <Button asChild variant="outline">
          <Link href="/scan">Scan a package</Link>
        </Button>
      </div>
    </div>
  );
}
