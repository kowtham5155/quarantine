'use client';

import { useActionState, useMemo, useState } from 'react';
import Link from 'next/link';
import { CheckCheck, RotateCcw, ShieldCheck } from 'lucide-react';

import { EmptyState } from '@/components/shared/EmptyState';
import { FormBanner } from '@/components/shared/FormFeedback';
import { PackageRef } from '@/components/shared/PackageRef';
import { TimeAgo } from '@/components/shared/TimeAgo';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { ecosystemSlug, versionHref } from '@/lib/routes';
import { safeText } from '@/lib/safe-display';
import type { ViolationRow } from '@/lib/services/governance.service';

import { triageViolationsAction } from '../actions';
import { initialGovernanceState } from '../governance-state';

export interface ViolationsInboxProps {
  rows: ViolationRow[];
  canTriage: boolean;
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

/**
 * The triage inbox.
 *
 * Selection is a real checkbox per row inside the form, so the ids that reach
 * the Server Action are the ones the reader ticked and the whole thing still
 * works without JavaScript. The action re-checks the permission and scopes its
 * update by `orgId`, so a forged id list changes nothing outside the tenant.
 */
export function ViolationsInbox({ rows, canTriage }: ViolationsInboxProps) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [state, action, pending] = useActionState(triageViolationsAction, initialGovernanceState);

  const allSelected = rows.length > 0 && selected.size === rows.length;
  const selectedRows = useMemo(
    () => rows.filter((row) => selected.has(row.id)),
    [rows, selected],
  );

  // Reopening only makes sense for something already closed, and resolving only
  // for something open — so the bar offers whichever the selection allows.
  const canResolve = selectedRows.some((row) => row.state !== 'RESOLVED');
  const canReopen = selectedRows.some((row) => row.state === 'RESOLVED');

  const toggle = (id: string, checked: boolean) => {
    setSelected((current) => {
      const next = new Set(current);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  };

  if (rows.length === 0) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="Nothing to triage"
        description="No violation in this view. That means either no policy has fired, or everything it caught has already been dealt with."
      />
    );
  }

  return (
    <form action={action} className="space-y-4">
      <FormBanner state={state} />

      {canTriage ? (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-surface/40 px-3 py-2">
          <label className="flex items-center gap-2 text-sm">
            <Checkbox
              checked={allSelected}
              aria-label="Select every violation in this view"
              onCheckedChange={(checked) =>
                setSelected(checked === true ? new Set(rows.map((row) => row.id)) : new Set())
              }
            />
            Select all
          </label>

          <span className="font-mono text-xs text-muted-foreground tabular-nums">
            {selected.size} selected
          </span>

          <div className="ml-auto flex flex-wrap items-center gap-2">
            <Button
              type="submit"
              name="state"
              value="RESOLVED"
              size="sm"
              disabled={pending || !canResolve}
            >
              <CheckCheck aria-hidden="true" />
              Mark resolved
            </Button>
            <Button
              type="submit"
              name="state"
              value="OPEN"
              size="sm"
              variant="outline"
              disabled={pending || !canReopen}
            >
              <RotateCcw aria-hidden="true" />
              Reopen
            </Button>
          </div>
        </div>
      ) : null}

      <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border">
        {rows.map((row) => (
          <li key={row.id} className="flex items-start gap-3 px-3 py-3">
            {canTriage ? (
              <Checkbox
                name="violationIds"
                value={row.id}
                checked={selected.has(row.id)}
                onCheckedChange={(checked) => toggle(row.id, checked === true)}
                aria-label={`Select the violation on ${row.name} ${row.version}`}
                className="mt-1"
              />
            ) : null}

            <div className="min-w-0 flex-1 space-y-1.5">
              <div className="flex flex-wrap items-center gap-2">
                <PackageRef
                  name={row.name}
                  version={row.version}
                  ecosystem={ecosystemSlug(row.ecosystem)}
                  href={versionHref(row.ecosystem, row.name, row.version)}
                  size="sm"
                />
                {row.verdict ? <VerdictBadge verdict={row.verdict} size="sm" /> : null}
                <Badge variant={ACTION_VARIANT[row.policyAction]} className="font-mono text-[10px]">
                  {row.policyAction.toLowerCase()}
                </Badge>
                <Badge variant={row.state === 'OPEN' ? 'default' : 'outline'} className="text-[10px]">
                  {STATE_LABEL[row.state]}
                </Badge>
              </div>

              <p className="text-xs text-muted-foreground">
                <Link href={`/policies/${row.policyId}`} className="hover:underline">
                  {safeText(row.policyName, { maxLength: 80 })}
                </Link>
                {row.projectId ? (
                  <>
                    {' · '}
                    <Link href={`/projects/${row.projectId}`} className="hover:underline">
                      {safeText(row.projectName ?? 'project', { maxLength: 60 })}
                    </Link>
                  </>
                ) : null}
                {' · '}
                <TimeAgo date={row.detectedAt} />
              </p>
            </div>

            {row.analysisId ? (
              <Button asChild variant="ghost" size="sm" className="shrink-0">
                <Link href={`/analyses/${row.analysisId}`}>Evidence</Link>
              </Button>
            ) : null}
          </li>
        ))}
      </ul>
    </form>
  );
}
