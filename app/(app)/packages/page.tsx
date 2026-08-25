import type { Metadata } from 'next';
import Link from 'next/link';
import { Radar } from 'lucide-react';

import { PageHeader } from '@/components/shared/PageHeader';
import { StatCard } from '@/components/shared/StatCard';
import { Button } from '@/components/ui/button';
import { requireAuthContext } from '@/lib/auth-context';
import { listPackages } from '@/lib/services/package.service';

import { PackagesTable } from './PackagesTable';

export const metadata: Metadata = { title: 'Packages' };

export default async function PackagesPage() {
  const ctx = await requireAuthContext();
  const { items, total, take } = await listPackages(ctx, { take: 200 });

  const flagged = items.filter(
    (item) =>
      item.worstVerdict === 'KNOWN_MALICIOUS' ||
      item.worstVerdict === 'LIKELY_MALICIOUS' ||
      item.worstVerdict === 'SUSPICIOUS',
  ).length;
  const clean = items.filter((item) => item.worstVerdict === 'CLEAN').length;

  return (
    <div className="space-y-8">
      <PageHeader
        title="Packages"
        description="Every package this organisation has analysed, with the worst verdict seen across its versions."
        actions={
          <Button asChild>
            <Link href="/scan">
              <Radar aria-hidden="true" />
              New scan
            </Link>
          </Button>
        }
      />

      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard label="Packages" value={total} hint="analysed by this organisation" />
        <StatCard label="Flagged" value={flagged} hint="suspicious or worse" />
        <StatCard label="Clean" value={clean} hint="no signal fired" />
      </div>

      {total > take ? (
        <p className="text-xs text-muted-foreground">
          Showing the first {take} of {total} packages, ordered by weekly downloads.
        </p>
      ) : null}

      <PackagesTable packages={items} />
    </div>
  );
}
