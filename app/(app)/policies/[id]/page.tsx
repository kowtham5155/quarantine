import type { Metadata } from 'next';
import { cache } from 'react';
import { notFound } from 'next/navigation';

import { PageHeader } from '@/components/shared/PageHeader';
import { TimeAgo } from '@/components/shared/TimeAgo';
import { Badge } from '@/components/ui/badge';
import { requireAuthContext } from '@/lib/auth-context';
import { NotFoundError } from '@/lib/errors';
import { can } from '@/lib/rbac';
import { safeText } from '@/lib/safe-display';
import * as policyService from '@/lib/services/policy.service';

import { PolicyForm } from '../PolicyForm';
import { loadRuleOptions } from '../rules';

interface PageProps {
  params: Promise<{ id: string }>;
}

const loadPolicy = cache(async (policyId: string) => {
  const ctx = await requireAuthContext();

  try {
    return await policyService.getPolicy(ctx, policyId);
  } catch (error) {
    // A policy id from another org is a 404, not a 403: the caller learns
    // nothing about whether it exists.
    if (error instanceof NotFoundError) notFound();
    throw error;
  }
});

async function readPolicyId(params: Promise<{ id: string }>): Promise<string> {
  const { id } = await params;
  if (typeof id !== 'string' || id.length === 0 || id.length > 64) notFound();
  return id;
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const policy = await loadPolicy(await readPolicyId(params));
  return { title: safeText(policy.name, { maxLength: 80 }) };
}

export default async function PolicyDetailPage({ params }: PageProps) {
  const policyId = await readPolicyId(params);
  const [ctx, policy, rules] = await Promise.all([
    requireAuthContext(),
    loadPolicy(policyId),
    loadRuleOptions(),
  ]);

  return (
    <div className="mx-auto max-w-3xl space-y-8">
      <PageHeader
        breadcrumbs={[
          { label: 'Policies', href: '/policies' },
          { label: safeText(policy.name, { maxLength: 40 }) },
        ]}
        title={safeText(policy.name, { maxLength: 80 })}
        description={
          policy.description ? safeText(policy.description, { maxLength: 300 }) : undefined
        }
        meta={
          <>
            <Badge
              variant={policy.enabled ? 'secondary' : 'outline'}
              className="font-mono text-[11px]"
            >
              {policy.enabled ? 'enforcing' : 'disabled'}
            </Badge>
            <span className="text-xs text-muted-foreground">
              {policy.openViolations.toLocaleString('en-GB')} open ·{' '}
              {policy.totalViolations.toLocaleString('en-GB')} total violations
            </span>
            <span className="text-xs text-muted-foreground">
              Updated <TimeAgo date={policy.updatedAt} />
            </span>
          </>
        }
      />

      {policy.droppedConditions > 0 ? (
        <p
          role="alert"
          className="rounded-md border border-verdict-suspicious-accent/40 bg-verdict-suspicious-surface px-3 py-2 text-sm text-verdict-suspicious-accent"
        >
          {policy.droppedConditions}{' '}
          {policy.droppedConditions === 1 ? 'condition is' : 'conditions are'} stored in a shape this
          build cannot read, and {policy.droppedConditions === 1 ? 'is' : 'are'} not shown below.
          Saving from this page replaces the stored set with what you see.
        </p>
      ) : null}

      <PolicyForm
        policy={policy}
        rules={rules}
        canDelete={can(ctx, 'policy:delete', { orgId: ctx.orgId })}
      />
    </div>
  );
}
