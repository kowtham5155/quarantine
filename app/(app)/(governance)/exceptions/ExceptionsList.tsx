'use client';

import { useActionState } from 'react';
import Link from 'next/link';
import { BookLock, Check, Loader2, X } from 'lucide-react';

import { EmptyState } from '@/components/shared/EmptyState';
import { FormBanner } from '@/components/shared/FormFeedback';
import { PackageRef } from '@/components/shared/PackageRef';
import { TimeAgo } from '@/components/shared/TimeAgo';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ecosystemSlug, versionHref } from '@/lib/routes';
import { safeText } from '@/lib/safe-display';
import type { ExceptionRow } from '@/lib/services/governance.service';

import { decideExceptionAction } from '../actions';
import { initialGovernanceState } from '../governance-state';

export interface ExceptionsListProps {
  rows: ExceptionRow[];
  /** Whether this viewer may decide requests at all. Ownership is re-checked server-side. */
  canDecide: boolean;
  /** The viewer, so the surface does not offer them their own request to approve. */
  viewerId: string;
}

const STATE_LABEL = {
  PENDING: 'Pending',
  APPROVED: 'Approved',
  DENIED: 'Denied',
  EXPIRED: 'Expired',
} as const;

const STATE_VARIANT = {
  PENDING: 'default',
  APPROVED: 'secondary',
  DENIED: 'outline',
  EXPIRED: 'outline',
} as const;

/** "in 12 days", or the fact that it never runs out. */
function Expiry({ row }: { row: ExceptionRow }) {
  if (row.expiresAt === null) {
    return (
      <span className="text-verdict-suspicious-accent">
        No expiry — enforcing never resumes on its own
      </span>
    );
  }

  if (row.state === 'EXPIRED' || row.lapsed) {
    return (
      <span>
        Expired <TimeAgo date={row.expiresAt} />
      </span>
    );
  }

  return (
    <span>
      Expires <TimeAgo date={row.expiresAt} />
    </span>
  );
}

function ExceptionItem({
  row,
  canDecide,
  viewerId,
}: {
  row: ExceptionRow;
  canDecide: boolean;
  viewerId: string;
}) {
  const [state, action, pending] = useActionState(decideExceptionAction, initialGovernanceState);

  // Nobody approves their own request — enforced in the service through the
  // RBAC ownership check; hidden here so the button is never offered.
  const decidable = canDecide && row.state === 'PENDING' && row.requestedById !== viewerId;

  return (
    <li className="space-y-3 px-3 py-3">
      <div className="flex flex-wrap items-start gap-2">
        <div className="min-w-0 flex-1 space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <PackageRef
              name={row.name}
              version={row.version}
              ecosystem={ecosystemSlug(row.ecosystem)}
              href={versionHref(row.ecosystem, row.name, row.version)}
              size="sm"
            />
            <Badge variant={STATE_VARIANT[row.state]} className="text-[10px]">
              {STATE_LABEL[row.state]}
            </Badge>
            {row.lapsed ? (
              <Badge variant="outline" className="text-[10px]">
                lapsed, awaiting sweep
              </Badge>
            ) : null}
            {row.policyId ? (
              <Link
                href={`/policies/${row.policyId}`}
                className="font-mono text-[11px] text-muted-foreground hover:underline"
              >
                {safeText(row.policyName ?? 'policy', { maxLength: 60 })}
              </Link>
            ) : (
              <span className="font-mono text-[11px] text-muted-foreground">every policy</span>
            )}
          </div>

          {/* Justification is user-written free text: bounded and stripped. */}
          <p className="text-sm">{safeText(row.justification, { maxLength: 1000 })}</p>

          <p className="text-xs text-muted-foreground">
            Requested by {safeText(row.requestedByName, { maxLength: 60 })}{' '}
            <TimeAgo date={row.createdAt} />
            {row.approvedByName
              ? ` · decided by ${safeText(row.approvedByName, { maxLength: 60 })}`
              : null}
            {' · '}
            <Expiry row={row} />
          </p>
        </div>
      </div>

      <FormBanner state={state} />

      {decidable ? (
        <form action={action} className="flex flex-wrap items-center gap-2">
          <input type="hidden" name="exceptionId" value={row.id} />
          <Button type="submit" name="decision" value="APPROVED" size="sm" disabled={pending}>
            {pending ? (
              <Loader2 aria-hidden="true" className="animate-spin" />
            ) : (
              <Check aria-hidden="true" />
            )}
            Approve
          </Button>
          <Button
            type="submit"
            name="decision"
            value="DENIED"
            size="sm"
            variant="outline"
            disabled={pending}
          >
            <X aria-hidden="true" />
            Deny
          </Button>
        </form>
      ) : null}

      {canDecide && row.state === 'PENDING' && row.requestedById === viewerId ? (
        <p className="text-xs text-muted-foreground">
          This is your own request. Another administrator has to decide it.
        </p>
      ) : null}
    </li>
  );
}

export function ExceptionsList({ rows, canDecide, viewerId }: ExceptionsListProps) {
  if (rows.length === 0) {
    return (
      <EmptyState
        icon={BookLock}
        title="No exceptions"
        description="An exception is a time-boxed, justified, approved way past a blocking policy. Nothing has needed one in this view."
      />
    );
  }

  return (
    <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border">
      {rows.map((row) => (
        <ExceptionItem key={row.id} row={row} canDecide={canDecide} viewerId={viewerId} />
      ))}
    </ul>
  );
}
