'use client';

import { useActionState, useState } from 'react';
import Link from 'next/link';
import { CircleCheck, Loader2, ShieldAlert, ShieldX } from 'lucide-react';

import { EmptyState } from '@/components/shared/EmptyState';
import { FormBanner } from '@/components/shared/FormFeedback';
import { PackageRef } from '@/components/shared/PackageRef';
import { TimeAgo } from '@/components/shared/TimeAgo';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { ecosystemSlug, versionHref } from '@/lib/routes';
import { safeText } from '@/lib/safe-display';
import type { QuarantineRow } from '@/lib/services/governance.service';

import { requestExceptionAction, reviewQuarantineAction } from '../actions';
import { initialGovernanceState } from '../governance-state';

export interface QuarantineListProps {
  rows: QuarantineRow[];
  canReview: boolean;
  canRequestException: boolean;
}

const STATE_LABEL = {
  HELD: 'Held',
  RELEASED: 'Released',
  CONFIRMED_BAD: 'Confirmed bad',
} as const;

/**
 * One held package, and the two things that can be done with it.
 *
 * Each row is its own form: a shared one would make "release" ambiguous about
 * which package it released, and a mis-click on a supply-chain hold is not a
 * cheap mistake.
 */
function QuarantineItem({
  row,
  canReview,
  canRequestException,
}: {
  row: QuarantineRow;
  canReview: boolean;
  canRequestException: boolean;
}) {
  const [state, action, pending] = useActionState(reviewQuarantineAction, initialGovernanceState);
  const [exceptionState, requestException, requesting] = useActionState(
    requestExceptionAction,
    initialGovernanceState,
  );
  const [showNote, setShowNote] = useState(false);
  const [showException, setShowException] = useState(false);

  const held = row.state === 'HELD';

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
            {row.verdict ? <VerdictBadge verdict={row.verdict} size="sm" /> : null}
            <Badge variant={held ? 'destructive' : 'outline'} className="text-[10px]">
              {STATE_LABEL[row.state]}
            </Badge>
          </div>

          {/* The reason is written by a policy but can quote a package-derived
              string, so it is bounded and stripped like any hostile input. */}
          <p className="text-sm text-muted-foreground">
            {safeText(row.reason, { maxLength: 300 })}
          </p>

          <p className="text-xs text-muted-foreground">
            Held <TimeAgo date={row.heldAt} />
            {row.policyNames.length > 0
              ? ` · ${row.policyNames.map((name) => safeText(name, { maxLength: 60 })).join(', ')}`
              : null}
            {row.reviewedAt ? (
              <>
                {' · reviewed '}
                <TimeAgo date={row.reviewedAt} />
                {row.reviewedByName
                  ? ` by ${safeText(row.reviewedByName, { maxLength: 60 })}`
                  : null}
              </>
            ) : null}
          </p>
        </div>

        {row.analysisId ? (
          <Button asChild variant="ghost" size="sm" className="shrink-0">
            <Link href={`/analyses/${row.analysisId}`}>Evidence</Link>
          </Button>
        ) : null}
      </div>

      <FormBanner state={state} />

      {canReview && held ? (
        <form action={action} className="space-y-3">
          <input type="hidden" name="itemId" value={row.id} />

          {showNote ? (
            <div className="space-y-1.5">
              <Label htmlFor={`note-${row.id}`} className="text-xs text-muted-foreground">
                Note — replaces the recorded reason
              </Label>
              <Textarea
                id={`note-${row.id}`}
                name="note"
                rows={2}
                maxLength={500}
                placeholder="What you checked, and what convinced you."
              />
            </div>
          ) : null}

          <div className="flex flex-wrap items-center gap-2">
            <Button
              type="submit"
              name="decision"
              value="RELEASED"
              size="sm"
              variant="outline"
              disabled={pending}
            >
              {pending ? (
                <Loader2 aria-hidden="true" className="animate-spin" />
              ) : (
                <CircleCheck aria-hidden="true" />
              )}
              Release
            </Button>
            <Button
              type="submit"
              name="decision"
              value="CONFIRMED_BAD"
              size="sm"
              variant="destructive"
              disabled={pending}
            >
              <ShieldX aria-hidden="true" />
              Confirm bad
            </Button>
            {!showNote ? (
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setShowNote(true)}
                disabled={pending}
              >
                Add a note
              </Button>
            ) : null}
          </div>
        </form>
      ) : null}

      {canRequestException && held ? (
        <div className="space-y-3">
          <FormBanner state={exceptionState} />

          {showException ? (
            /* Requesting is not deciding: this records a request that an
               administrator other than the requester has to approve before the
               hold lifts. */
            <form action={requestException} className="space-y-3 rounded-md border border-border p-3">
              <input type="hidden" name="packageVersionId" value={row.packageVersionId} />

              <div className="space-y-1.5">
                <Label htmlFor={`justification-${row.id}`} className="text-xs">
                  Why this is acceptable
                </Label>
                <Textarea
                  id={`justification-${row.id}`}
                  name="justification"
                  rows={3}
                  required
                  minLength={20}
                  maxLength={1000}
                  placeholder="What you checked, what the package actually does, and what happens if you are wrong."
                />
              </div>

              <div className="space-y-1.5">
                <Label htmlFor={`expires-${row.id}`} className="text-xs">
                  Expires in (days)
                </Label>
                <Input
                  id={`expires-${row.id}`}
                  name="expiresInDays"
                  type="number"
                  min={1}
                  max={365}
                  defaultValue={30}
                  className="w-32"
                />
                <p className="text-xs text-muted-foreground">
                  Leave it blank for no expiry — an approver then has to accept that enforcing
                  never resumes on its own.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <Button type="submit" size="sm" variant="outline" disabled={requesting}>
                  {requesting ? <Loader2 aria-hidden="true" className="animate-spin" /> : null}
                  {requesting ? 'Requesting…' : 'Request exception'}
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  onClick={() => setShowException(false)}
                  disabled={requesting}
                >
                  Cancel
                </Button>
              </div>
            </form>
          ) : (
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={() => setShowException(true)}
            >
              Request an exception
            </Button>
          )}
        </div>
      ) : null}
    </li>
  );
}

export function QuarantineList({ rows, canReview, canRequestException }: QuarantineListProps) {
  if (rows.length === 0) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="Nothing is held"
        description="A blocking policy puts a package here when it fires. An empty hold list with no policies enforcing means nothing is being stopped, not that nothing is wrong."
      />
    );
  }

  return (
    <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border">
      {rows.map((row) => (
        <QuarantineItem
          key={row.id}
          row={row}
          canReview={canReview}
          canRequestException={canRequestException}
        />
      ))}
    </ul>
  );
}
