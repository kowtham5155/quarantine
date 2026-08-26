import type { Metadata } from 'next';
import Link from 'next/link';
import { Plus } from 'lucide-react';

import { PageHeader } from '@/components/shared/PageHeader';
import { StatCard } from '@/components/shared/StatCard';
import { Button } from '@/components/ui/button';
import { requireAuthContext } from '@/lib/auth-context';
import { can } from '@/lib/rbac';
import * as policyService from '@/lib/services/policy.service';

import { PoliciesTable } from './PoliciesTable';

export const metadata: Metadata = { title: 'Policies' };

export default async function PoliciesPage() {
  const ctx = await requireAuthContext();
  const policies = await policyService.listPolicies(ctx);

  const enforcing = policies.filter((policy) => policy.enabled).length;
  const blocking = policies.filter((policy) => policy.enabled && policy.action === 'BLOCK').length;
  const open = policies.reduce((total, policy) => total + policy.openViolations, 0);
  const canEdit = can(ctx, 'policy:update', { orgId: ctx.orgId });

  return (
    <div className="space-y-8">
      <PageHeader
        title="Policies"
        description="What this organisation does about what the engine finds. Evaluated in priority order on every completed analysis; the first match decides."
        actions={
          can(ctx, 'policy:create', { orgId: ctx.orgId }) ? (
            <Button asChild>
              <Link href="/policies/new">
                <Plus aria-hidden="true" />
                New policy
              </Link>
            </Button>
          ) : null
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Policies" value={policies.length} />
        <StatCard label="Enforcing" value={enforcing} hint="evaluated on every analysis" />
        <StatCard label="Blocking" value={blocking} hint="can hold a package" />
        <StatCard label="Open violations" value={open} hint="across every policy" />
      </div>

      <PoliciesTable policies={policies} canEdit={canEdit} />
    </div>
  );
}
