import Link from 'next/link';
import { CircleSlash, PackageCheck, ShieldAlert, ShieldX } from 'lucide-react';

import { StatCard } from '@/components/shared/StatCard';
import { VerdictDistribution } from '@/components/shared/VerdictDistribution';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { requireAuthContext } from '@/lib/auth-context';
import { VERDICTS } from '@/lib/constants';
import { can } from '@/lib/rbac';
import * as projectService from '@/lib/services/project.service';

import { DependencyTree } from './DependencyTree';
import { ProjectActions } from './ProjectActions';
import { loadDependencies, loadProject, readProjectId } from './project';

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function ProjectTreePage({ params }: PageProps) {
  const projectId = await readProjectId(params);
  const ctx = await requireAuthContext();

  const [project, rows] = await Promise.all([loadProject(projectId), loadDependencies(projectId)]);

  // Summarised from the rows just read rather than from the cached column: the
  // cache is written at import time and a dependency analysed since then would
  // otherwise show as unanalysed here.
  const risk = projectService.summariseRisk(rows);
  const tree = projectService.buildTree(rows);

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Dependencies"
          value={risk.total}
          hint={`${risk.direct} direct · ${risk.transitive} transitive`}
          icon={PackageCheck}
        />
        <StatCard
          label="Flagged"
          value={risk.flagged}
          hint="suspicious or worse"
          icon={ShieldAlert}
        />
        <StatCard label="Held" value={risk.blocked} hint="in quarantine" icon={ShieldX} />
        <StatCard
          label="Not analysed"
          value={risk.unanalysed}
          hint="no verdict is not a clean verdict"
          icon={CircleSlash}
        />
      </div>

      <ProjectActions
        projectId={project.id}
        unanalysed={risk.unanalysed}
        queueLimit={projectService.PROJECT_QUEUE_LIMIT}
        canImport={can(ctx, 'project:update', { orgId: ctx.orgId })}
        canScan={can(ctx, 'analysis:create', { orgId: ctx.orgId })}
      />

      <div className="grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Dependency tree</CardTitle>
            <CardDescription>
              Every package this project resolves to, with this organisation&rsquo;s verdict on each
              one. Direct dependencies are open; their transitive tail is collapsed.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <DependencyTree nodes={tree} flaggedCount={risk.flagged} />
          </CardContent>
        </Card>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Verdict spread</CardTitle>
              <CardDescription>
                {risk.analysed.toLocaleString('en-GB')} of {risk.total.toLocaleString('en-GB')}{' '}
                dependencies have been analysed.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <VerdictDistribution
                slices={VERDICTS.map((verdict) => ({
                  verdict,
                  count: risk.byVerdict[verdict],
                }))}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Where to look next</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <Button asChild variant="outline" className="w-full justify-start">
                <Link href={`/projects/${project.id}/dependencies`}>
                  Flat dependency table, with depth and path
                </Link>
              </Button>
              <Button asChild variant="outline" className="w-full justify-start">
                <Link href={`/projects/${project.id}/violations`}>
                  Policy violations raised against this project
                </Link>
              </Button>
              <Button asChild variant="outline" className="w-full justify-start">
                <Link href={`/projects/${project.id}/sbom`}>Export a CycloneDX SBOM</Link>
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
