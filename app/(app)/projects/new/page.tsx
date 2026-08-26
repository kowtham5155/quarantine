import type { Metadata } from 'next';

import { PageHeader } from '@/components/shared/PageHeader';
import { requireAuthContext } from '@/lib/auth-context';
import { can } from '@/lib/rbac';
import { forbidden } from '@/lib/route-guards';

import { NewProjectForm } from './NewProjectForm';

export const metadata: Metadata = { title: 'New project' };

export default async function NewProjectPage() {
  const ctx = await requireAuthContext();
  if (!can(ctx, 'project:create', { orgId: ctx.orgId })) forbidden();

  return (
    <div className="mx-auto max-w-3xl space-y-8">
      <PageHeader
        title="New project"
        description="Point Quarantine at a dependency graph and it will tell you what is in it."
        breadcrumbs={[{ label: 'Projects', href: '/projects' }, { label: 'New project' }]}
      />
      <NewProjectForm />
    </div>
  );
}
