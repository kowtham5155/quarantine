import type { Metadata } from 'next';
import { QuarantineState } from '@prisma/client';

import { PageHeader } from '@/components/shared/PageHeader';
import { StatCard } from '@/components/shared/StatCard';
import { SubNav } from '@/components/shared/SubNav';
import { requireAuthContext } from '@/lib/auth-context';
import { can } from '@/lib/rbac';
import * as governanceService from '@/lib/services/governance.service';

import { QuarantineList } from './QuarantineList';

export const metadata: Metadata = { title: 'Quarantine' };

interface PageProps {
  searchParams: Promise<{ state?: string }>;
}

function readState(value: string | undefined): QuarantineState | undefined {
  if (value === 'RELEASED') return QuarantineState.RELEASED;
  if (value === 'CONFIRMED_BAD') return QuarantineState.CONFIRMED_BAD;
  if (value === 'HELD') return QuarantineState.HELD;
  return undefined;
}

export default async function QuarantinePage({ searchParams }: PageProps) {
  const { state } = await searchParams;
  const ctx = await requireAuthContext();

  // Counts come from the unfiltered read so the tabs stay honest whichever tab
  // is open; the list below is the filtered view.
  const all = await governanceService.listQuarantine(ctx);
  const selected = readState(state);
  const rows = selected ? all.filter((row) => row.state === selected) : all;

  const held = all.filter((row) => row.state === 'HELD').length;
  const released = all.filter((row) => row.state === 'RELEASED').length;
  const confirmed = all.filter((row) => row.state === 'CONFIRMED_BAD').length;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Quarantine"
        description="Packages a blocking policy is holding. Nothing here is installed anywhere by this tool — the hold is a decision about what your builds are allowed to pull."
      />

      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard label="Held" value={held} hint="awaiting a decision" />
        <StatCard label="Released" value={released} hint="reviewed and allowed" />
        <StatCard label="Confirmed bad" value={confirmed} hint="reviewed and refused" />
      </div>

      <SubNav
        ariaLabel="Quarantine state"
        items={[
          { label: 'All', href: '/quarantine', count: all.length },
          { label: 'Held', href: '/quarantine?state=HELD', count: held },
          { label: 'Released', href: '/quarantine?state=RELEASED', count: released },
          {
            label: 'Confirmed bad',
            href: '/quarantine?state=CONFIRMED_BAD',
            count: confirmed,
          },
        ]}
      />

      <QuarantineList
        rows={rows}
        canReview={can(ctx, 'quarantine:review', { orgId: ctx.orgId })}
        canRequestException={can(ctx, 'exception:request', { orgId: ctx.orgId })}
      />
    </div>
  );
}
