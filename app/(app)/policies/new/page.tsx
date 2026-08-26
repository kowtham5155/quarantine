import type { Metadata } from 'next';

import { PageHeader } from '@/components/shared/PageHeader';
import { requireAuthContext } from '@/lib/auth-context';
import { can } from '@/lib/rbac';
import { forbidden } from '@/lib/route-guards';

import { PolicyForm } from '../PolicyForm';
import { loadRuleOptions } from '../rules';

export const metadata: Metadata = { title: 'New policy' };

export default async function NewPolicyPage() {
  const ctx = await requireAuthContext();
  if (!can(ctx, 'policy:create', { orgId: ctx.orgId })) forbidden();

  const rules = await loadRuleOptions();

  return (
    <div className="mx-auto max-w-3xl space-y-8">
      <PageHeader
        breadcrumbs={[{ label: 'Policies', href: '/policies' }, { label: 'New' }]}
        title="New policy"
        description="Describe the packages you care about, then say what should happen when one turns up. Preview it against what has already been analysed before you enforce it."
      />

      <PolicyForm rules={rules} />
    </div>
  );
}
