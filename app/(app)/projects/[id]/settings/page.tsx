import type { Metadata } from 'next';

import { requireAuthContext } from '@/lib/auth-context';
import { can } from '@/lib/rbac';

import { loadProject, readProjectId } from '../project';
import { ProjectSettingsForm } from './ProjectSettingsForm';

export const metadata: Metadata = { title: 'Project settings' };

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function ProjectSettingsPage({ params }: PageProps) {
  const projectId = await readProjectId(params);
  const [ctx, project] = await Promise.all([requireAuthContext(), loadProject(projectId)]);

  return (
    <ProjectSettingsForm
      project={project}
      canEdit={can(ctx, 'project:update', { orgId: ctx.orgId })}
      canDelete={can(ctx, 'project:delete', { orgId: ctx.orgId })}
    />
  );
}
