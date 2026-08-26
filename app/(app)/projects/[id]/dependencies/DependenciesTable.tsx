'use client';

import Link from 'next/link';
import { Boxes } from 'lucide-react';

import { DataTable, type DataTableColumn } from '@/components/shared/DataTable';
import { EmptyState } from '@/components/shared/EmptyState';
import { PackageRef } from '@/components/shared/PackageRef';
import { TimeAgo } from '@/components/shared/TimeAgo';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { VERDICT_META } from '@/lib/constants';
import { ecosystemSlug, versionHref } from '@/lib/routes';
import { safeText } from '@/lib/safe-display';
import type { DependencyRow } from '@/lib/services/project.service';

export interface DependenciesTableProps {
  rows: DependencyRow[];
}

/** The route from the project root to this package, e.g. `express › body-parser`. */
function DependencyPath({ path }: { path: string[] }) {
  if (path.length === 0) {
    return <span className="text-xs text-muted-foreground">direct</span>;
  }

  const full = path.map((segment) => safeText(segment, { maxLength: 120 })).join(' › ');
  const shown =
    path.length <= 2
      ? full
      : `${safeText(path[0]!, { maxLength: 60 })} › … › ${safeText(path.at(-1)!, { maxLength: 60 })}`;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="line-clamp-1 font-mono text-xs text-muted-foreground">{shown}</span>
      </TooltipTrigger>
      <TooltipContent className="max-w-sm">
        <span className="font-mono text-xs break-words">{full}</span>
      </TooltipContent>
    </Tooltip>
  );
}

export function DependenciesTable({ rows }: DependenciesTableProps) {
  const columns: Array<DataTableColumn<DependencyRow>> = [
    {
      id: 'package',
      header: 'Package',
      cell: (row) => (
        <PackageRef
          name={row.name}
          version={row.version}
          ecosystem={ecosystemSlug(row.ecosystem)}
          href={versionHref(row.ecosystem, row.name, row.version)}
          size="sm"
        />
      ),
      sortValue: (row) => row.name,
      searchValue: (row) => `${row.name} ${row.version} ${row.path.join(' ')}`,
    },
    {
      id: 'scope',
      header: 'Scope',
      cell: (row) => (
        <Badge variant={row.isDirect ? 'secondary' : 'outline'} className="text-[11px]">
          {row.isDirect ? 'direct' : 'transitive'}
        </Badge>
      ),
      sortValue: (row) => (row.isDirect ? 0 : 1),
      hideBelowSm: true,
    },
    {
      id: 'depth',
      header: 'Depth',
      align: 'right',
      cell: (row) => <span className="font-mono text-xs tabular-nums">{row.depth}</span>,
      sortValue: (row) => row.depth,
      hideBelowSm: true,
    },
    {
      id: 'path',
      header: 'Reached via',
      cell: (row) => <DependencyPath path={row.path} />,
      sortValue: (row) => row.path.join(' › '),
      hideBelowSm: true,
    },
    {
      id: 'verdict',
      header: 'Verdict',
      cell: (row) =>
        row.verdict ? (
          <div className="flex items-center gap-2">
            <VerdictBadge verdict={row.verdict} size="sm" />
            {row.quarantined ? (
              <Badge variant="destructive" className="text-[10px]">
                held
              </Badge>
            ) : null}
          </div>
        ) : (
          <span className="text-xs text-muted-foreground">Not analysed</span>
        ),
      sortValue: (row) => (row.verdict ? VERDICT_META[row.verdict].rank : 99),
    },
    {
      id: 'analysed',
      header: 'Analysed',
      align: 'right',
      cell: (row) =>
        row.analysedAt && row.analysisId ? (
          <Link href={`/analyses/${row.analysisId}`} className="text-xs hover:underline">
            <TimeAgo date={row.analysedAt} className="text-muted-foreground" />
          </Link>
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        ),
      sortValue: (row) => row.analysedAt,
      hideBelowSm: true,
    },
  ];

  return (
    <DataTable
      data={rows}
      columns={columns}
      getRowId={(row) => row.id}
      searchPlaceholder="Search this graph…"
      caption="Every dependency in this project, flattened"
      initialSort={{ columnId: 'verdict', direction: 'asc' }}
      pageSize={50}
      facets={[
        {
          id: 'scope',
          label: 'Scope',
          options: [
            { value: 'direct', label: 'Direct' },
            { value: 'transitive', label: 'Transitive' },
          ],
          accessor: (row) => (row.isDirect ? 'direct' : 'transitive'),
        },
        {
          id: 'verdict',
          label: 'Verdict',
          options: [
            { value: 'KNOWN_MALICIOUS', label: 'Known malicious' },
            { value: 'LIKELY_MALICIOUS', label: 'Likely malicious' },
            { value: 'SUSPICIOUS', label: 'Suspicious' },
            { value: 'LOW_RISK', label: 'Low risk' },
            { value: 'CLEAN', label: 'Clean' },
            { value: 'NONE', label: 'Not analysed' },
          ],
          accessor: (row) => row.verdict ?? 'NONE',
        },
      ]}
      emptyState={
        <EmptyState
          icon={Boxes}
          title="No dependencies recorded"
          description="Import this project's lockfile from the tree tab and every coordinate in it appears here."
        />
      }
      noResultsState={<EmptyState size="sm" icon={Boxes} title="Nothing matches that filter" />}
    />
  );
}
