'use client';

import Link from 'next/link';
import { Layers } from 'lucide-react';

import { DataTable, type DataTableColumn } from '@/components/shared/DataTable';
import { EmptyState } from '@/components/shared/EmptyState';
import { TimeAgo } from '@/components/shared/TimeAgo';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { VERDICT_META } from '@/lib/constants';
import { safeText } from '@/lib/safe-display';
import type { ProjectSummary } from '@/lib/services/project.service';

export interface ProjectsTableProps {
  projects: ProjectSummary[];
}

/** Coverage bar: how much of the graph has actually been looked at. */
function Coverage({ analysed, total }: { analysed: number; total: number }) {
  if (total === 0) return <span className="text-xs text-muted-foreground">No graph yet</span>;

  const percent = Math.round((analysed / total) * 100);

  return (
    <div className="min-w-24 space-y-1">
      <p className="font-mono text-xs tabular-nums">{percent}%</p>
      <div
        className="h-1.5 w-full overflow-hidden rounded-full bg-muted"
        role="img"
        aria-label={`${analysed} of ${total} dependencies analysed`}
      >
        <div className="h-full rounded-full bg-accent" style={{ width: `${percent}%` }} />
      </div>
    </div>
  );
}

export function ProjectsTable({ projects }: ProjectsTableProps) {
  const columns: Array<DataTableColumn<ProjectSummary>> = [
    {
      id: 'name',
      header: 'Project',
      cell: (row) => (
        <div className="min-w-0 space-y-0.5">
          <Link href={`/projects/${row.id}`} className="font-medium hover:underline">
            {safeText(row.name, { maxLength: 80 })}
          </Link>
          {row.description ? (
            <p className="line-clamp-1 text-xs text-muted-foreground">
              {safeText(row.description, { maxLength: 160 })}
            </p>
          ) : null}
        </div>
      ),
      sortValue: (row) => row.name,
      searchValue: (row) => `${row.name} ${row.description ?? ''}`,
    },
    {
      id: 'source',
      header: 'Source',
      cell: (row) => (
        <Badge variant="secondary" className="font-mono text-[11px]">
          {row.source === 'GITHUB' ? 'github' : 'lockfile'}
        </Badge>
      ),
      sortValue: (row) => row.source,
      hideBelowSm: true,
    },
    {
      id: 'dependencies',
      header: 'Dependencies',
      align: 'right',
      cell: (row) => (
        <span className="font-mono text-xs tabular-nums">
          {row.dependencyCount.toLocaleString('en-GB')}
          {row.risk ? (
            <span className="text-muted-foreground"> · {row.risk.direct} direct</span>
          ) : null}
        </span>
      ),
      sortValue: (row) => row.dependencyCount,
    },
    {
      id: 'worst',
      header: 'Worst verdict',
      cell: (row) =>
        row.risk?.worstVerdict ? (
          <VerdictBadge verdict={row.risk.worstVerdict} size="sm" />
        ) : (
          <span className="text-xs text-muted-foreground">
            {row.dependencyCount === 0 ? '—' : 'Nothing flagged'}
          </span>
        ),
      sortValue: (row) => (row.risk?.worstVerdict ? VERDICT_META[row.risk.worstVerdict].rank : 99),
    },
    {
      id: 'flagged',
      header: 'Flagged',
      align: 'right',
      cell: (row) => (
        <span className="font-mono text-xs tabular-nums">{row.risk?.flagged ?? 0}</span>
      ),
      sortValue: (row) => row.risk?.flagged ?? 0,
      hideBelowSm: true,
    },
    {
      id: 'coverage',
      header: 'Analysed',
      cell: (row) => <Coverage analysed={row.risk?.analysed ?? 0} total={row.dependencyCount} />,
      sortValue: (row) =>
        row.dependencyCount === 0 ? -1 : (row.risk?.analysed ?? 0) / row.dependencyCount,
      hideBelowSm: true,
    },
    {
      id: 'scanned',
      header: 'Last import',
      align: 'right',
      cell: (row) =>
        row.lastScanAt ? (
          <TimeAgo date={row.lastScanAt} className="text-xs text-muted-foreground" />
        ) : (
          <span className="text-xs text-muted-foreground">Never</span>
        ),
      sortValue: (row) => row.lastScanAt,
    },
  ];

  return (
    <DataTable
      data={projects}
      columns={columns}
      getRowId={(row) => row.id}
      searchPlaceholder="Search projects…"
      caption="Projects in this organisation"
      initialSort={{ columnId: 'worst', direction: 'asc' }}
      facets={[
        {
          id: 'source',
          label: 'Source',
          options: [
            { value: 'UPLOAD', label: 'Lockfile upload' },
            { value: 'GITHUB', label: 'GitHub repository' },
          ],
          accessor: (row) => row.source,
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
      ]}
      emptyState={
        <EmptyState
          icon={Layers}
          title="No projects yet"
          description="A project holds a dependency graph. Upload a lockfile and every package in it is checked against this organisation's policy."
          action={
            <Button asChild size="sm">
              <Link href="/projects/new">Create a project</Link>
            </Button>
          }
        />
      }
      noResultsState={<EmptyState size="sm" icon={Layers} title="Nothing matches that filter" />}
    />
  );
}
