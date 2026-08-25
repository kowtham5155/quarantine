import Link from 'next/link';
import { PackageX } from 'lucide-react';

import { Button } from '@/components/ui/button';

export default function PackageNotFound() {
  return (
    <div className="flex min-h-[50svh] flex-col items-center justify-center gap-6 text-center">
      <div className="flex size-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
        <PackageX aria-hidden="true" className="size-6" />
      </div>
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">Not analysed here</h1>
        <p className="max-w-md text-sm text-balance text-muted-foreground">
          This organisation has no analysis for that package. Scanning it will create one — verdicts
          are never shared between organisations.
        </p>
      </div>
      <div className="flex flex-wrap items-center justify-center gap-2">
        <Button asChild>
          <Link href="/scan">Scan it</Link>
        </Button>
        <Button asChild variant="outline">
          <Link href="/packages">All packages</Link>
        </Button>
      </div>
    </div>
  );
}
