'use client';

import Link from 'next/link';
import { ShieldCheck } from 'lucide-react';

import { DataTable, type DataTableColumn } from '@/components/shared/DataTable';
import { EmptyState } from '@/components/shared/EmptyState';
import { PackageRef } from '@/components/shared/PackageRef';
import { TimeAgo } from '@/components/shared/TimeAgo';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Badge } from '@/components/ui/badge';
import { ecosystemSlug, versionHref } from '@/lib/routes';
import { safeText } from '@/lib/safe-display';
import type { ViolationRow } from '@/lib/services/governance.service';

export interface ProjectViolationsTableProps {
  rows: ViolationRow[];
}

const ACTION_VARIANT = {
  BLOCK: 'destructive',
  WARN: 'secondary',
  ALLOW: 'outline',
} as const;

const STATE_LABEL = {
  OPEN: 'Open',
  EXCEPTED: 'Excepted',
  RESOLVED: 'Resolved',
} as const;

export function ProjectViolationsTable({ rows }: ProjectViolationsTableProps) {
  const columns: Array<DataTableColumn<ViolationRow>> = [
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
      searchValue: (row) => `${row.name} ${row.version} ${row.policyName}`,
    },
    {
      id: 'policy',
      header: 'Policy',
      cell: (row) => (
        <Link href={`/policies/${row.policyId}`} className="text-sm hover:underline">
          {safeText(row.policyName, { maxLength: 80 })}
        </Link>
      ),
      sortValue: (row) => row.policyName,
    },
    {
      id: 'action',
      header: 'Action',
      cell: (row) => (
        <Badge variant={ACTION_VARIANT[row.policyAction]} className="font-mono text-[11px]">
          {row.policyAction.toLowerCase()}
        </Badge>
      ),
      sortValue: (row) => row.policyAction,
      hideBelowSm: true,
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
      sortValue: (row) => row.verdict ?? 'ZZ',
      hideBelowSm: true,
    },
    {
      id: 'state',
      header: 'State',
      cell: (row) => (
        <Badge variant={row.state === 'OPEN' ? 'default' : 'outline'} className="text-[11px]">
          {STATE_LABEL[row.state]}
        </Badge>
      ),
      sortValue: (row) => row.state,
    },
    {
      id: 'detected',
      header: 'Detected',
      align: 'right',
      cell: (row) => <TimeAgo date={row.detectedAt} className="text-xs text-muted-foreground" />,
      sortValue: (row) => row.detectedAt,
      hideBelowSm: true,
    },
  ];

  return (
    <DataTable
      data={rows}
      columns={columns}
      getRowId={(row) => row.id}
      searchPlaceholder="Search violations…"
      caption="Policy violations raised against this project"
      initialSort={{ columnId: 'detected', direction: 'desc' }}
      facets={[
        {
          id: 'state',
          label: 'State',
          options: [
            { value: 'OPEN', label: 'Open' },
            { value: 'EXCEPTED', label: 'Excepted' },
            { value: 'RESOLVED', label: 'Resolved' },
          ],
          accessor: (row) => row.state,
        },
        {
          id: 'action',
          label: 'Action',
          options: [
            { value: 'BLOCK', label: 'Block' },
            { value: 'WARN', label: 'Warn' },
            { value: 'ALLOW', label: 'Allow' },
          ],
          accessor: (row) => row.policyAction,
        },
      ]}
      emptyState={
        <EmptyState
          icon={ShieldCheck}
          title="No policy has fired on this project"
          description="Nothing in this graph has broken a rule this organisation enforces. A dependency with no verdict has not been cleared — it has not been looked at."
        />
      }
      noResultsState={
        <EmptyState size="sm" icon={ShieldCheck} title="Nothing matches that filter" />
      }
    />
  );
}
