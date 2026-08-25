import type { Metadata } from 'next';
import Link from 'next/link';
import { ShieldCheck } from 'lucide-react';

import { PageHeader } from '@/components/shared/PageHeader';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { requireAuthContext } from '@/lib/auth-context';
import { SIGNAL_FAMILIES, SIGNAL_FAMILY_META } from '@/lib/constants';

import { ScanForm } from './ScanForm';

export const metadata: Metadata = { title: 'New scan' };

export default async function ScanPage() {
  // Not used for display — this is the authorisation check for the page itself.
  await requireAuthContext();

  return (
    <div className="space-y-8">
      <PageHeader
        title="Scan a package"
        description="Paste a package name or upload a lockfile. The engine downloads the published artefact, extracts it under a hard budget, and reads it statically — nothing in it is ever executed."
      />

      <ScanForm />

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">What runs, in order</CardTitle>
            <CardDescription>
              Each family is scored independently and reports its own timing. A family that fails
              lowers confidence rather than failing the analysis.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="grid gap-2 sm:grid-cols-2">
              {SIGNAL_FAMILIES.map((family) => (
                <li key={family} className="text-sm">
                  <span className="font-medium">{SIGNAL_FAMILY_META[family].label}</span>
                  <p className="text-xs text-muted-foreground">
                    {SIGNAL_FAMILY_META[family].description}
                  </p>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldCheck aria-hidden="true" className="size-4 text-primary" />
              Handling
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm text-muted-foreground">
            <p>
              Extraction is capped at 50MB, 10,000 entries and 10MB per file, into a per-scan
              directory that is deleted when the scan ends.
            </p>
            <p>
              Package contents are never executed, required or evaluated — see the{' '}
              <Link href="/security" className="text-primary underline-offset-4 hover:underline">
                threat model
              </Link>
              .
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
