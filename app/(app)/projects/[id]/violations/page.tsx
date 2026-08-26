import type { Metadata } from 'next';
import Link from 'next/link';
import { Siren } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { requireAuthContext } from '@/lib/auth-context';
import * as governanceService from '@/lib/services/governance.service';

import { readProjectId } from '../project';
import { ProjectViolationsTable } from './ProjectViolationsTable';

export const metadata: Metadata = { title: 'Violations' };

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function ProjectViolationsPage({ params }: PageProps) {
  const projectId = await readProjectId(params);
  const ctx = await requireAuthContext();

  // Scoped to this project. The org-wide counts the service returns describe the
  // whole inbox, so the numbers shown here are counted from these rows instead.
  const inbox = await governanceService.listViolations(ctx, { projectId, take: 500 });
  const open = inbox.items.filter((row) => row.state === 'OPEN').length;
  const blocking = inbox.items.filter(
    (row) => row.state === 'OPEN' && row.policyAction === 'BLOCK',
  ).length;

  return (
    <Card>
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="space-y-1.5">
          <CardTitle className="text-base">Policy violations</CardTitle>
          <CardDescription>
            {inbox.items.length === 0
              ? 'Nothing here has broken a policy.'
              : `${open.toLocaleString('en-GB')} open · ${blocking.toLocaleString('en-GB')} of them blocking.`}{' '}
            Triage — resolving, or granting a time-boxed exception — happens in the org-wide inbox.
          </CardDescription>
        </div>
        <Button asChild variant="outline" size="sm">
          <Link href="/violations">
            <Siren aria-hidden="true" />
            Open the inbox
          </Link>
        </Button>
      </CardHeader>
      <CardContent>
        <ProjectViolationsTable rows={inbox.items} />
      </CardContent>
    </Card>
  );
}
