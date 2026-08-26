import { cache } from 'react';
import { notFound } from 'next/navigation';

import { requireAuthContext } from '@/lib/auth-context';
import { NotFoundError } from '@/lib/errors';
import * as projectService from '@/lib/services/project.service';

/**
 * Loading one project, once per request.
 *
 * The layout, the page and `generateMetadata` all need the same rows;
 * `React.cache` deduplicates them inside a single render pass. A project id
 * belonging to another org throws NotFoundError from the service and becomes a
 * 404 here — the caller learns nothing about whether the id exists.
 */

export async function readProjectId(params: Promise<{ id: string }>): Promise<string> {
  const { id } = await params;
  if (typeof id !== 'string' || id.length === 0 || id.length > 64) notFound();
  return id;
}

export const loadProject = cache(async (projectId: string) => {
  const ctx = await requireAuthContext();

  try {
    return await projectService.get(ctx, projectId);
  } catch (error) {
    if (error instanceof NotFoundError) notFound();
    throw error;
  }
});

export const loadDependencies = cache(async (projectId: string) => {
  const ctx = await requireAuthContext();

  try {
    return await projectService.listDependencies(ctx, projectId);
  } catch (error) {
    if (error instanceof NotFoundError) notFound();
    throw error;
  }
});
