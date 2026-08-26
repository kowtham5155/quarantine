'use client';

import { useActionState } from 'react';
import Link from 'next/link';
import { ShieldCheck } from 'lucide-react';

import { DataTable, type DataTableColumn } from '@/components/shared/DataTable';
import { EmptyState } from '@/components/shared/EmptyState';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { describeCondition } from '@/lib/policy-conditions';
import type { PolicySummary } from '@/lib/services/policy.service';
import { safeText } from '@/lib/safe-display';

import { setPolicyEnabledAction } from './actions';
import { initialPolicyState } from './policy-state';

export interface PoliciesTableProps {
  policies: PolicySummary[];
  canEdit: boolean;
}

const ACTION_VARIANT = {
  BLOCK: 'destructive',
  WARN: 'secondary',
  ALLOW: 'outline',
} as const;

/**
 * The enforcing switch.
 *
 * A form rather than an onChange handler: toggling enforcement is a privileged
 * mutation, and routing it through a Server Action keeps the permission check
 * and the audit entry on the server where they belong.
 */
function EnabledSwitch({ policy, canEdit }: { policy: PolicySummary; canEdit: boolean }) {
  const [, action, pending] = useActionState(setPolicyEnabledAction, initialPolicyState);

  if (!canEdit) {
    return (
      <Badge variant={policy.enabled ? 'secondary' : 'outline'} className="text-[11px]">
        {policy.enabled ? 'Enforcing' : 'Off'}
      </Badge>
    );
  }

  return (
    <form action={action} id={`toggle-${policy.id}`}>
      <input type="hidden" name="policyId" value={policy.id} />
      <input type="hidden" name="enabled" value={policy.enabled ? 'false' : 'true'} />
      <Switch
        checked={policy.enabled}
        disabled={pending}
        aria-label={`${policy.enabled ? 'Disable' : 'Enable'} ${policy.name}`}
        onCheckedChange={() => {
          (
            document.getElementById(`toggle-${policy.id}`) as HTMLFormElement | null
          )?.requestSubmit();
        }}
      />
    </form>
  );
}

export function PoliciesTable({ policies, canEdit }: PoliciesTableProps) {
  const columns: Array<DataTableColumn<PolicySummary>> = [
    {
      id: 'priority',
      header: 'Priority',
      align: 'right',
      cell: (row) => <span className="font-mono text-xs tabular-nums">{row.priority}</span>,
      sortValue: (row) => row.priority,
    },
    {
      id: 'name',
      header: 'Policy',
      cell: (row) => (
        <div className="min-w-0 space-y-0.5">
          <Link href={`/policies/${row.id}`} className="font-medium hover:underline">
            {safeText(row.name, { maxLength: 80 })}
          </Link>
          <p className="line-clamp-1 text-xs text-muted-foreground">
            {row.conditions.length === 0
              ? 'No readable conditions — matches nothing.'
              : row.conditions.map(describeCondition).join(' and ')}
          </p>
        </div>
      ),
      sortValue: (row) => row.name,
      searchValue: (row) =>
        `${row.name} ${row.description ?? ''} ${row.conditions.map(describeCondition).join(' ')}`,
    },
    {
      id: 'action',
      header: 'Action',
      cell: (row) => (
        <Badge variant={ACTION_VARIANT[row.action]} className="font-mono text-[11px]">
          {row.action.toLowerCase()}
        </Badge>
      ),
      sortValue: (row) => row.action,
    },
    {
      id: 'violations',
      header: 'Open violations',
      align: 'right',
      cell: (row) => (
        <span className="font-mono text-xs tabular-nums">
          {row.openViolations.toLocaleString('en-GB')}
          {row.totalViolations > row.openViolations ? (
            <span className="text-muted-foreground">
              {' '}
              / {row.totalViolations.toLocaleString('en-GB')}
            </span>
          ) : null}
        </span>
      ),
      sortValue: (row) => row.openViolations,
      hideBelowSm: true,
    },
    {
      id: 'enabled',
      header: 'Enforcing',
      cell: (row) => <EnabledSwitch policy={row} canEdit={canEdit} />,
      sortValue: (row) => row.enabled,
    },
  ];

  return (
    <DataTable
      data={policies}
      columns={columns}
      getRowId={(row) => row.id}
      searchPlaceholder="Search policies…"
      caption="Policies in evaluation order"
      initialSort={{ columnId: 'priority', direction: 'asc' }}
      facets={[
        {
          id: 'action',
          label: 'Action',
          options: [
            { value: 'BLOCK', label: 'Block' },
            { value: 'WARN', label: 'Warn' },
            { value: 'ALLOW', label: 'Allow' },
          ],
          accessor: (row) => row.action,
        },
        {
          id: 'enabled',
          label: 'State',
          options: [
            { value: 'on', label: 'Enforcing' },
            { value: 'off', label: 'Disabled' },
          ],
          accessor: (row) => (row.enabled ? 'on' : 'off'),
        },
      ]}
      emptyState={
        <EmptyState
          icon={ShieldCheck}
          title="No policies yet"
          description="Without a policy nothing is ever blocked — every analysis is recorded and nothing acts on it. Start with one that blocks anything likely malicious."
          action={
            canEdit ? (
              <Button asChild size="sm">
                <Link href="/policies/new">Create a policy</Link>
              </Button>
            ) : undefined
          }
        />
      }
      noResultsState={
        <EmptyState size="sm" icon={ShieldCheck} title="Nothing matches that filter" />
      }
    />
  );
}
