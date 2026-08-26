'use server';

import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { Ecosystem, ProjectSource } from '@prisma/client';

import { requestFingerprint, requireAuthContext } from '@/lib/auth-context';
import { ValidationError } from '@/lib/errors';
import { field, optionalField } from '@/lib/form-state';
import { toFormState } from '@/lib/form-state.server';
import { MAX_LOCKFILE_BYTES } from '@/lib/lockfile';
import { bucketKey, enforce } from '@/lib/rate-limit';
import * as projectService from '@/lib/services/project.service';

import { type ProjectFormState } from './project-state';

/**
 * Project mutations.
 *
 * A lockfile is read as text and handed to a pure parser; it is never written
 * to disk and nothing in it is executed or installed (THE SAFETY RULE).
 */

async function projectContext() {
  const ctx = await requireAuthContext();
  const { ip, userAgent } = await requestFingerprint();
  return { ctx: { ...ctx, actorEmail: ctx.email }, request: { ip, userAgent } };
}

async function readLockfile(formData: FormData): Promise<{ name: string; content: string } | null> {
  const file = formData.get('lockfile');
  if (!(file instanceof File) || file.size === 0) return null;

  if (file.size > MAX_LOCKFILE_BYTES) {
    throw new ValidationError('That lockfile is too large to read.', {
      details: {
        fieldErrors: {
          lockfile: [`Lockfiles are limited to ${MAX_LOCKFILE_BYTES / (1024 * 1024)}MB.`],
        },
      },
    });
  }

  return { name: file.name, content: await file.text() };
}

/** Create a project, optionally seeding its graph from an uploaded lockfile. */
export async function createProjectAction(
  _previous: ProjectFormState,
  formData: FormData,
): Promise<ProjectFormState> {
  let projectId: string;

  try {
    const { ctx, request } = await projectContext();
    await enforce('scanCreate', bucketKey('scanCreate', { org: ctx.orgId, user: ctx.userId }));

    const source =
      optionalField(formData, 'source') === 'GITHUB' ? ProjectSource.GITHUB : ProjectSource.UPLOAD;
    const repoUrl = optionalField(formData, 'repoUrl');

    if (source === ProjectSource.GITHUB && !repoUrl) {
      throw new ValidationError('Enter the repository URL.', {
        details: { fieldErrors: { repoUrl: ['Enter the repository URL.'] } },
      });
    }

    const project = await projectService.create(
      ctx,
      {
        name: field(formData, 'name'),
        ...(optionalField(formData, 'description')
          ? { description: field(formData, 'description') }
          : {}),
        ecosystem: optionalField(formData, 'ecosystem') === 'PYPI' ? Ecosystem.PYPI : Ecosystem.NPM,
        source,
        ...(repoUrl ? { repoUrl } : {}),
      },
      request,
    );

    projectId = project.id;

    const lockfile = await readLockfile(formData);
    if (lockfile) {
      await projectService.importLockfile(ctx, project.id, lockfile, request);
    }
  } catch (error) {
    return toFormState(error);
  }

  // Outside the try: `redirect` throws by design, and swallowing it here would
  // leave the user on the form after the project was created.
  redirect(`/projects/${projectId}`);
}

export async function importLockfileAction(
  _previous: ProjectFormState,
  formData: FormData,
): Promise<ProjectFormState> {
  try {
    const { ctx, request } = await projectContext();
    const projectId = field(formData, 'projectId');

    const lockfile = await readLockfile(formData);
    if (!lockfile) {
      throw new ValidationError('Choose a lockfile to upload.', {
        details: { fieldErrors: { lockfile: ['Choose a lockfile to upload.'] } },
      });
    }

    const result = await projectService.importLockfile(ctx, projectId, lockfile, request);

    revalidatePath(`/projects/${projectId}`);

    return {
      status: 'success',
      message: `Read ${result.imported} dependencies from that ${result.kind} file.`,
      projectId,
      imported: {
        kind: result.kind,
        found: result.found,
        imported: result.imported,
        direct: result.direct,
        truncated: result.truncated,
      },
    };
  } catch (error) {
    return toFormState(error);
  }
}

/** Queue analyses for the project's unanalysed dependencies, up to the cap. */
export async function scanDependenciesAction(
  _previous: ProjectFormState,
  formData: FormData,
): Promise<ProjectFormState> {
  try {
    const { ctx, request } = await projectContext();
    await enforce('scanCreate', bucketKey('scanCreate', { org: ctx.orgId, user: ctx.userId }));

    const projectId = field(formData, 'projectId');
    const outcome = await projectService.queueDependencyAnalyses(ctx, projectId, request);

    revalidatePath(`/projects/${projectId}`);

    return {
      status: 'success',
      message:
        outcome.queued === 0
          ? 'Every dependency already has an analysis.'
          : `Queued ${outcome.queued} analyses.${outcome.remaining > 0 ? ` ${outcome.remaining} still to go.` : ''}`,
      projectId,
      queued: outcome,
    };
  } catch (error) {
    return toFormState(error);
  }
}

export async function updateProjectAction(
  _previous: ProjectFormState,
  formData: FormData,
): Promise<ProjectFormState> {
  try {
    const { ctx, request } = await projectContext();
    const projectId = field(formData, 'projectId');

    await projectService.update(
      ctx,
      projectId,
      {
        name: field(formData, 'name'),
        ...(optionalField(formData, 'description')
          ? { description: field(formData, 'description') }
          : {}),
        ...(optionalField(formData, 'repoUrl') ? { repoUrl: field(formData, 'repoUrl') } : {}),
      },
      request,
    );

    revalidatePath(`/projects/${projectId}`);

    return { status: 'success', message: 'Project updated.', projectId };
  } catch (error) {
    return toFormState(error);
  }
}

export async function deleteProjectAction(
  _previous: ProjectFormState,
  formData: FormData,
): Promise<ProjectFormState> {
  try {
    const { ctx, request } = await projectContext();
    await projectService.remove(ctx, field(formData, 'projectId'), request);
  } catch (error) {
    return toFormState(error);
  }

  redirect('/projects');
}
