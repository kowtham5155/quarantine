import type { Metadata } from 'next';
import { ExceptionState } from '@prisma/client';

import { PageHeader } from '@/components/shared/PageHeader';
import { StatCard } from '@/components/shared/StatCard';
import { SubNav } from '@/components/shared/SubNav';
import { requireAuthContext } from '@/lib/auth-context';
import { hasRoleAtLeast, Role } from '@/lib/rbac';
import * as governanceService from '@/lib/services/governance.service';

import { ExceptionsList } from './ExceptionsList';

export const metadata: Metadata = { title: 'Exceptions' };

interface PageProps {
  searchParams: Promise<{ state?: string }>;
}

function readState(value: string | undefined): ExceptionState | undefined {
  if (value === 'PENDING') return ExceptionState.PENDING;
  if (value === 'APPROVED') return ExceptionState.APPROVED;
  if (value === 'DENIED') return ExceptionState.DENIED;
  if (value === 'EXPIRED') return ExceptionState.EXPIRED;
  return undefined;
}

export default async function ExceptionsPage({ searchParams }: PageProps) {
  const { state } = await searchParams;
  const ctx = await requireAuthContext();

  // Tidy the register before reading it, so nothing sits here looking live that
  // enforcement already treats as expired. Enforcement checks the clock itself
  // on every evaluation, so this is bookkeeping rather than a control.
  await governanceService.sweepExpiredExceptions({ ...ctx, actorEmail: ctx.email });

  const all = await governanceService.listExceptions(ctx);
  const selected = readState(state);
  const rows = selected ? all.filter((row) => row.state === selected) : all;

  const counts = {
    pending: all.filter((row) => row.state === 'PENDING').length,
    approved: all.filter((row) => row.state === 'APPROVED').length,
    denied: all.filter((row) => row.state === 'DENIED').length,
    expired: all.filter((row) => row.state === 'EXPIRED').length,
  };

  const indefinite = all.filter(
    (row) => row.state === 'APPROVED' && row.expiresAt === null,
  ).length;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Exceptions"
        description="A justified, approved, time-boxed way past a blocking policy. When one expires the violations it was suppressing reopen on their own."
      />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Pending" value={counts.pending} hint="waiting on an approver" />
        <StatCard label="Approved" value={counts.approved} hint="currently suppressing" />
        <StatCard
          label="Never expire"
          value={indefinite}
          hint={indefinite === 0 ? 'nothing is permanent' : 'enforcing never resumes'}
        />
        <StatCard label="Expired" value={counts.expired} hint="back to enforcing" />
      </div>

      <SubNav
        ariaLabel="Exception state"
        items={[
          { label: 'All', href: '/exceptions', count: all.length },
          { label: 'Pending', href: '/exceptions?state=PENDING', count: counts.pending },
          { label: 'Approved', href: '/exceptions?state=APPROVED', count: counts.approved },
          { label: 'Denied', href: '/exceptions?state=DENIED', count: counts.denied },
          { label: 'Expired', href: '/exceptions?state=EXPIRED', count: counts.expired },
        ]}
      />

      <ExceptionsList
        rows={rows}
        canDecide={hasRoleAtLeast(ctx.role, Role.ADMIN)}
        viewerId={ctx.userId}
      />
    </div>
  );
}
