import type { Metadata } from 'next';
import { ViolationState } from '@prisma/client';

import { PageHeader } from '@/components/shared/PageHeader';
import { SubNav } from '@/components/shared/SubNav';
import { requireAuthContext } from '@/lib/auth-context';
import { can } from '@/lib/rbac';
import * as governanceService from '@/lib/services/governance.service';

import { ViolationsInbox } from './ViolationsInbox';

export const metadata: Metadata = { title: 'Violations' };

interface PageProps {
  searchParams: Promise<{ state?: string }>;
}

/** The filter is a URL, so a triage view can be linked to and bookmarked. */
function readState(value: string | undefined): ViolationState | undefined {
  if (value === 'RESOLVED') return ViolationState.RESOLVED;
  if (value === 'EXCEPTED') return ViolationState.EXCEPTED;
  if (value === 'OPEN') return ViolationState.OPEN;
  return undefined;
}

export default async function ViolationsPage({ searchParams }: PageProps) {
  const { state } = await searchParams;
  const ctx = await requireAuthContext();

  const selected = readState(state);
  const inbox = await governanceService.listViolations(ctx, {
    ...(selected ? { state: selected } : {}),
    take: 300,
  });

  const total = inbox.counts.OPEN + inbox.counts.EXCEPTED + inbox.counts.RESOLVED;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Violations"
        description="Every time a policy fired, and what was done about it. A violation is a record of a decision the system made — resolving one is you agreeing with it, or overriding it."
      />

      <SubNav
        ariaLabel="Violation state"
        items={[
          { label: 'All', href: '/violations', count: total },
          { label: 'Open', href: '/violations?state=OPEN', count: inbox.counts.OPEN },
          {
            label: 'Excepted',
            href: '/violations?state=EXCEPTED',
            count: inbox.counts.EXCEPTED,
          },
          {
            label: 'Resolved',
            href: '/violations?state=RESOLVED',
            count: inbox.counts.RESOLVED,
          },
        ]}
      />

      {inbox.total > inbox.items.length ? (
        <p className="text-xs text-muted-foreground">
          Showing the {inbox.items.length.toLocaleString('en-GB')} most recent of{' '}
          {inbox.total.toLocaleString('en-GB')} in this view.
        </p>
      ) : null}

      <ViolationsInbox
        rows={inbox.items}
        canTriage={can(ctx, 'violation:triage', { orgId: ctx.orgId })}
      />
    </div>
  );
}
