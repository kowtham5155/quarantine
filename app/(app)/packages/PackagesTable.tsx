'use client';

import { PackageSearch } from 'lucide-react';

import { DataTable, type DataTableColumn } from '@/components/shared/DataTable';
import { EmptyState } from '@/components/shared/EmptyState';
import { PackageRef } from '@/components/shared/PackageRef';
import { SignalBadge } from '@/components/shared/SignalBadge';
import { TimeAgo } from '@/components/shared/TimeAgo';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Button } from '@/components/ui/button';
import { SIGNAL_FAMILIES, SIGNAL_FAMILY_META, VERDICTS, VERDICT_META } from '@/lib/constants';
import { ecosystemSlug, packageHref } from '@/lib/routes';
import type { PackageListItem } from '@/lib/services/package.service';

export interface PackagesTableProps {
  packages: PackageListItem[];
}

/**
 * Everything the organisation has analysed.
 *
 * Filtering is client-side over one already-bounded page from the service: an
 * org's analysed catalogue is hundreds of rows, not millions, and doing it here
 * keeps the facets instant. The service still caps what it returns.
 */
export function PackagesTable({ packages }: PackagesTableProps) {
  const columns: Array<DataTableColumn<PackageListItem>> = [
    {
      id: 'name',
      header: 'Package',
      cell: (row) => (
        <div className="min-w-0 space-y-0.5">
          <PackageRef
            name={row.name}
            ecosystem={ecosystemSlug(row.ecosystem)}
            href={packageHref(row.ecosystem, row.name)}
            hideEcosystem
          />
          {row.description ? (
            <p className="line-clamp-1 text-xs text-muted-foreground">{row.description}</p>
          ) : null}
        </div>
      ),
      sortValue: (row) => row.name,
      searchValue: (row) => `${row.name} ${row.description ?? ''}`,
      className: 'max-w-xs',
    },
    {
      id: 'ecosystem',
      header: 'Registry',
      cell: (row) => (
        <span className="font-mono text-xs text-muted-foreground uppercase">
          {ecosystemSlug(row.ecosystem)}
        </span>
      ),
      sortValue: (row) => row.ecosystem,
      hideBelowSm: true,
    },
    {
      id: 'worst',
      header: 'Worst verdict',
      cell: (row) =>
        row.worstVerdict ? (
          <VerdictBadge verdict={row.worstVerdict} size="sm" />
        ) : (
          <span className="text-xs text-muted-foreground">Pending</span>
        ),
      sortValue: (row) => (row.worstVerdict ? VERDICT_META[row.worstVerdict].rank : 99),
      searchValue: (row) => (row.worstVerdict ? VERDICT_META[row.worstVerdict].label : ''),
    },
    {
      id: 'families',
      header: 'Families fired',
      cell: (row) =>
        row.families.length === 0 ? (
          <span className="text-xs text-muted-foreground">None</span>
        ) : (
          <div className="flex flex-wrap gap-1">
            {row.families.map((family) => (
              <SignalBadge key={family} family={family} compact />
            ))}
          </div>
        ),
      sortValue: (row) => row.families.length,
      hideBelowSm: true,
    },
    {
      id: 'versions',
      header: 'Versions',
      align: 'right',
      cell: (row) => <span className="font-mono text-xs tabular-nums">{row.versionsAnalysed}</span>,
      sortValue: (row) => row.versionsAnalysed,
      hideBelowSm: true,
    },
    {
      id: 'downloads',
      header: 'Weekly downloads',
      align: 'right',
      cell: (row) => (
        <span className="font-mono text-xs tabular-nums">
          {row.weeklyDownloads.toLocaleString('en-GB')}
        </span>
      ),
      sortValue: (row) => row.weeklyDownloads,
      hideBelowSm: true,
    },
    {
      id: 'analysed',
      header: 'Last analysed',
      align: 'right',
      cell: (row) =>
        row.lastAnalysedAt ? (
          <TimeAgo date={row.lastAnalysedAt} className="text-xs text-muted-foreground" />
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        ),
      sortValue: (row) => row.lastAnalysedAt,
    },
  ];

  return (
    <DataTable
      data={packages}
      columns={columns}
      getRowId={(row) => `${row.ecosystem}:${row.name}`}
      searchPlaceholder="Search analysed packages…"
      caption="Packages analysed by this organisation"
      initialSort={{ columnId: 'worst', direction: 'asc' }}
      facets={[
        {
          id: 'verdict',
          label: 'Verdict',
          options: VERDICTS.map((verdict) => ({
            value: verdict,
            label: VERDICT_META[verdict].label,
          })),
          accessor: (row) => row.worstVerdict,
        },
        {
          id: 'ecosystem',
          label: 'Registry',
          options: [
            { value: 'NPM', label: 'npm' },
            { value: 'PYPI', label: 'PyPI' },
          ],
          accessor: (row) => row.ecosystem,
        },
        {
          id: 'family',
          label: 'Family',
          options: SIGNAL_FAMILIES.map((family) => ({
            value: family,
            label: SIGNAL_FAMILY_META[family].label,
          })),
          accessor: (row) => row.families,
        },
      ]}
      emptyState={
        <EmptyState
          icon={PackageSearch}
          title="No packages analysed yet"
          description="Scan a package or upload a lockfile and it will appear here with its verdict."
          action={
            <Button asChild size="sm">
              <a href="/scan">Scan a package</a>
            </Button>
          }
        />
      }
      noResultsState={
        <EmptyState
          size="sm"
          icon={PackageSearch}
          title="Nothing matches that filter"
          description="Try a different verdict, registry or search term."
        />
      }
    />
  );
}
