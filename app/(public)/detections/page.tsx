import type { Metadata } from 'next';
import Link from 'next/link';

import { PageHeader } from '@/components/shared/PageHeader';
import { StatCard } from '@/components/shared/StatCard';
import { SIGNAL_FAMILY_META, isSignalFamily } from '@/lib/constants';
import { getRuleCatalogue } from '@/lib/services/catalogue.service';

import { RuleCatalogue } from './RuleCatalogue';

export const metadata: Metadata = {
  title: 'Detections',
  description:
    'The complete Quarantine rule catalogue: every detection, its family, severity, weight, remediation and known false positives.',
};

export default async function DetectionsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const requested = Array.isArray(params.family) ? params.family[0] : params.family;
  const initialFamily = isSignalFamily(requested) ? requested : undefined;

  const catalogue = await getRuleCatalogue();

  return (
    <div className="space-y-8">
      <PageHeader
        title="Detection catalogue"
        description="Every rule the engine evaluates, published in full. A detection you cannot inspect is a detection you will eventually ignore — so the weights, the remediation and the known false positives are all here."
        meta={
          initialFamily ? (
            <span className="text-sm text-muted-foreground">
              Filtered to {SIGNAL_FAMILY_META[initialFamily].label} ·{' '}
              <Link href="/detections" className="text-primary underline-offset-4 hover:underline">
                show all families
              </Link>
            </span>
          ) : null
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Rules" value={catalogue.total} hint="across six families" />
        <StatCard label="Enabled" value={catalogue.enabled} hint="evaluated on every scan" />
        <StatCard label="Families" value={catalogue.byFamily.length} hint="scored independently" />
        <StatCard
          label="Largest family"
          value={
            catalogue.byFamily.reduce(
              (best, row) => (row.count > best.count ? row : best),
              catalogue.byFamily[0] ?? { family: 'INSTALL' as const, count: 0, enabled: 0 },
            ).count
          }
          hint={
            SIGNAL_FAMILY_META[
              catalogue.byFamily.reduce(
                (best, row) => (row.count > best.count ? row : best),
                catalogue.byFamily[0] ?? { family: 'INSTALL' as const, count: 0, enabled: 0 },
              ).family
            ].label
          }
        />
      </div>

      <RuleCatalogue rules={catalogue.rules} {...(initialFamily ? { initialFamily } : {})} />
    </div>
  );
}
