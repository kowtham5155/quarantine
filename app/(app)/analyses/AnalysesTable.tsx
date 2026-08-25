'use client';

import { Activity } from 'lucide-react';

import { DataTable, type DataTableColumn } from '@/components/shared/DataTable';
import { EmptyState } from '@/components/shared/EmptyState';
import { PackageRef } from '@/components/shared/PackageRef';
import { TimeAgo } from '@/components/shared/TimeAgo';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { VERDICTS, VERDICT_META, type Verdict } from '@/lib/constants';
import { ecosystemSlug, versionHref } from '@/lib/routes';

export interface AnalysisRow {
  id: string;
  ecosystem: 'NPM' | 'PYPI';
  name: string;
  version: string;
  status: string;
  verdict: Verdict | null;
  confidence: number | null;
  weightedScore: number | null;
  durationMs: number | null;
  createdAt: string;
  completedAt: string | null;
}

const STATUSES = ['QUEUED', 'RUNNING', 'COMPLETED', 'PARTIAL', 'FAILED'] as const;

/** Analysis history: one row per run, including the ones that failed. */
export function AnalysesTable({ analyses }: { analyses: AnalysisRow[] }) {
  const columns: Array<DataTableColumn<AnalysisRow>> = [
    {
      id: 'package',
      header: 'Package',
      cell: (row) => (
        <PackageRef
          name={row.name}
          version={row.version}
          ecosystem={ecosystemSlug(row.ecosystem)}
          href={versionHref(row.ecosystem, row.name, row.version)}
        />
      ),
      sortValue: (row) => row.name,
      searchValue: (row) => `${row.name} ${row.version}`,
    },
    {
      id: 'status',
      header: 'Status',
      cell: (row) => (
        <Badge variant={row.status === 'FAILED' ? 'destructive' : 'secondary'} className="text-xs">
          {row.status}
        </Badge>
      ),
      sortValue: (row) => row.status,
    },
    {
      id: 'verdict',
      header: 'Verdict',
      cell: (row) =>
        row.verdict ? (
          <VerdictBadge verdict={row.verdict} size="sm" />
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        ),
      sortValue: (row) => (row.verdict ? VERDICT_META[row.verdict].rank : 99),
    },
    {
      id: 'score',
      header: 'Score',
      align: 'right',
      cell: (row) => (
        <span className="font-mono text-xs tabular-nums">
          {row.weightedScore === null ? '—' : row.weightedScore.toFixed(1)}
        </span>
      ),
      sortValue: (row) => row.weightedScore,
      hideBelowSm: true,
    },
    {
      id: 'confidence',
      header: 'Confidence',
      align: 'right',
      cell: (row) => (
        <span className="font-mono text-xs tabular-nums">
          {row.confidence === null ? '—' : `${Math.round(row.confidence * 100)}%`}
        </span>
      ),
      sortValue: (row) => row.confidence,
      hideBelowSm: true,
    },
    {
      id: 'duration',
      header: 'Duration',
      align: 'right',
      cell: (row) => (
        <span className="font-mono text-xs tabular-nums">
          {row.durationMs === null ? '—' : `${(row.durationMs / 1000).toFixed(1)}s`}
        </span>
      ),
      sortValue: (row) => row.durationMs,
      hideBelowSm: true,
    },
    {
      id: 'when',
      header: 'Run',
      align: 'right',
      cell: (row) => (
        <TimeAgo
          date={row.completedAt ?? row.createdAt}
          className="text-xs text-muted-foreground"
        />
      ),
      sortValue: (row) => new Date(row.completedAt ?? row.createdAt),
    },
    {
      id: 'open',
      header: '',
      cell: (row) => (
        <Button asChild size="sm" variant="ghost">
          <a href={`/analyses/${row.id}`}>Detail</a>
        </Button>
      ),
    },
  ];

  return (
    <DataTable
      data={analyses}
      columns={columns}
      getRowId={(row) => row.id}
      searchPlaceholder="Search by package or version…"
      caption="Analysis history"
      initialSort={{ columnId: 'when', direction: 'desc' }}
      facets={[
        {
          id: 'status',
          label: 'Status',
          options: STATUSES.map((status) => ({ value: status, label: status })),
          accessor: (row) => row.status,
        },
        {
          id: 'verdict',
          label: 'Verdict',
          options: VERDICTS.map((verdict) => ({
            value: verdict,
            label: VERDICT_META[verdict].label,
          })),
          accessor: (row) => row.verdict,
        },
      ]}
      emptyState={
        <EmptyState
          icon={Activity}
          title="No analyses yet"
          description="Queue a scan and its run history appears here — including the runs that fail."
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
          icon={Activity}
          title="Nothing matches that filter"
          description="Try a different status or verdict."
        />
      }
    />
  );
}
