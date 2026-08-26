import type { Metadata } from 'next';
import Link from 'next/link';
import { FolderPlus } from 'lucide-react';

import { PageHeader } from '@/components/shared/PageHeader';
import { StatCard } from '@/components/shared/StatCard';
import { Button } from '@/components/ui/button';
import { requireAuthContext } from '@/lib/auth-context';
import * as projectService from '@/lib/services/project.service';

import { ProjectsTable } from './ProjectsTable';

export const metadata: Metadata = { title: 'Projects' };

export default async function ProjectsPage() {
  const ctx = await requireAuthContext();
  const projects = await projectService.listForOrg(ctx);

  const dependencies = projects.reduce((total, project) => total + project.dependencyCount, 0);
  const flagged = projects.reduce((total, project) => total + (project.risk?.flagged ?? 0), 0);
  const unanalysed = projects.reduce(
    (total, project) => total + (project.risk?.unanalysed ?? 0),
    0,
  );

  return (
    <div className="space-y-8">
      <PageHeader
        title="Projects"
        description="Each project is a dependency graph: what you actually install, with a verdict on every package in it."
        actions={
          <Button asChild>
            <Link href="/projects/new">
              <FolderPlus aria-hidden="true" />
              New project
            </Link>
          </Button>
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Projects" value={projects.length} />
        <StatCard label="Dependencies" value={dependencies} hint="across every project graph" />
        <StatCard label="Flagged" value={flagged} hint="suspicious or worse" />
        <StatCard
          label="Not yet analysed"
          value={unanalysed}
          hint="no verdict means not ruled out"
        />
      </div>

      <ProjectsTable projects={projects} />
    </div>
  );
}
