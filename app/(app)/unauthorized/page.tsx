import type { Metadata } from 'next';
import Link from 'next/link';
import { ShieldX } from 'lucide-react';

import { EmptyState } from '@/components/shared/EmptyState';
import { PageHeader } from '@/components/shared/PageHeader';
import { Button } from '@/components/ui/button';
import { requireAuthContext } from '@/lib/auth-context';
import { ROLE_PERMISSIONS } from '@/lib/rbac';

export const metadata: Metadata = { title: 'Not permitted' };

/**
 * Where a page-level guard sends someone whose role cannot use the surface
 * they asked for.
 *
 * It says which role they hold, because "access denied" with no explanation is
 * the most common way an authorisation system gets worked around: the user asks
 * a colleague to run it for them instead of asking for the right role. It does
 * not enumerate what the *other* roles can do, and it never says whether the
 * thing they asked for exists.
 */
export default async function UnauthorizedPage() {
  const ctx = await requireAuthContext();
  const granted = ROLE_PERMISSIONS[ctx.role].size;

  return (
    <div className="space-y-8">
      <PageHeader
        title="Your role cannot open that"
        description="The action was refused before anything was read or written."
      />

      <EmptyState
        icon={ShieldX}
        title={`You are signed in as ${ctx.role.toLowerCase()}`}
        description={`That role holds ${granted} permissions, and the one this page needs is not among them. An organisation owner or administrator can change your role from the members settings.`}
        action={
          <Button asChild size="sm">
            <Link href="/dashboard">Back to the dashboard</Link>
          </Button>
        }
        footer={
          <Link href="/packages" className="text-xs underline underline-offset-2">
            Browse what this organisation has analysed
          </Link>
        }
      />
    </div>
  );
}
