import type { Metadata } from 'next';
import type { ReactNode } from 'react';

import { PageHeader } from '@/components/shared/PageHeader';
import { SubNav } from '@/components/shared/SubNav';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { safeText } from '@/lib/safe-display';

import { loadProject, readProjectId } from './project';

interface LayoutProps {
  children: ReactNode;
  params: Promise<{ id: string }>;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ id: string }>;
}): Promise<Metadata> {
  const project = await loadProject(await readProjectId(params));
  return { title: safeText(project.name, { maxLength: 80 }) };
}

export default async function ProjectLayout({ children, params }: LayoutProps) {
  const projectId = await readProjectId(params);
  const project = await loadProject(projectId);

  const base = `/projects/${project.id}`;

  return (
    <div className="space-y-6">
      <PageHeader
        separated={false}
        breadcrumbs={[
          { label: 'Projects', href: '/projects' },
          { label: safeText(project.name, { maxLength: 40 }) },
        ]}
        title={safeText(project.name, { maxLength: 80 })}
        description={
          project.description ? safeText(project.description, { maxLength: 300 }) : undefined
        }
        meta={
          <>
            {project.risk?.worstVerdict ? (
              <VerdictBadge verdict={project.risk.worstVerdict} appearance="solid" />
            ) : (
              <Badge variant="secondary">
                {project.dependencyCount === 0 ? 'No graph yet' : 'Nothing flagged'}
              </Badge>
            )}
            <span className="font-mono text-xs text-muted-foreground">
              {project.dependencyCount.toLocaleString('en-GB')} dependencies
            </span>
            <Badge variant="outline" className="font-mono text-[11px]">
              {project.ecosystem === 'NPM' ? 'npm' : 'pypi'}
            </Badge>
          </>
        }
        actions={
          project.repoUrl ? (
            <Button asChild variant="outline">
              {/* Package- and user-supplied URLs open with no referrer and no
                  window handle back into this origin. */}
              <a href={project.repoUrl} rel="noopener noreferrer nofollow" target="_blank">
                Repository
              </a>
            </Button>
          ) : null
        }
      />

      <SubNav
        ariaLabel="Project sections"
        items={[
          { label: 'Tree', href: base },
          { label: 'Dependencies', href: `${base}/dependencies`, count: project.dependencyCount },
          { label: 'Violations', href: `${base}/violations` },
          { label: 'SBOM', href: `${base}/sbom` },
          { label: 'History', href: `${base}/history` },
          { label: 'Settings', href: `${base}/settings` },
        ]}
      />

      <div>{children}</div>
    </div>
  );
}
