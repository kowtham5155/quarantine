import { Ecosystem, ProjectSource } from '@prisma/client';
import { z } from 'zod';

import { audit } from '@/lib/audit';
import { prisma } from '@/lib/db';
import { NotFoundError, ValidationError } from '@/lib/errors';
import { assertCan, type AuthContext } from '@/lib/rbac';

/**
 * Projects — the org-scoped container a dependency tree is scanned against.
 *
 * Only the parts onboarding needs exist here; the full project surface (lockfile
 * ingestion, dependency trees, SBOM export) arrives with the projects routes.
 * Every query is filtered on `ctx.orgId` per CLAUDE.md rule 4.
 */

export interface RequestInfo {
  ip?: string | null;
  userAgent?: string | null;
}

export const createProjectSchema = z.object({
  name: z.string().trim().min(2, 'Enter a project name.').max(80),
  description: z.string().trim().max(500).optional(),
  ecosystem: z.nativeEnum(Ecosystem).default(Ecosystem.NPM),
  source: z.nativeEnum(ProjectSource).default(ProjectSource.UPLOAD),
  repoUrl: z.string().trim().url('Enter a valid URL.').max(500).optional(),
});

export interface ProjectSummary {
  id: string;
  name: string;
  description: string | null;
  ecosystem: Ecosystem;
  source: ProjectSource;
  repoUrl: string | null;
  lastScanAt: Date | null;
  dependencyCount: number;
  createdAt: Date;
}

export async function create(
  ctx: AuthContext & { actorEmail: string },
  input: z.infer<typeof createProjectSchema>,
  request: RequestInfo = {},
): Promise<ProjectSummary> {
  assertCan(ctx, 'project:create', { orgId: ctx.orgId });

  const parsed = createProjectSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const { name, description, ecosystem, source, repoUrl } = parsed.data;

  const clash = await prisma.project.findFirst({
    where: { orgId: ctx.orgId, name },
    select: { id: true },
  });
  if (clash) {
    throw new ValidationError('A project with that name already exists.', {
      details: { fieldErrors: { name: ['A project with that name already exists.'] } },
    });
  }

  const project = await prisma.project.create({
    data: {
      orgId: ctx.orgId,
      name,
      description: description ?? null,
      ecosystem,
      source,
      repoUrl: repoUrl ?? null,
    },
  });

  await audit(
    ctx,
    'project.created',
    { type: 'Project', id: project.id },
    { name, ecosystem, source },
    request,
  );

  return {
    id: project.id,
    name: project.name,
    description: project.description,
    ecosystem: project.ecosystem,
    source: project.source,
    repoUrl: project.repoUrl,
    lastScanAt: project.lastScanAt,
    dependencyCount: 0,
    createdAt: project.createdAt,
  };
}

export async function listForOrg(
  ctx: AuthContext & { actorEmail: string },
): Promise<ProjectSummary[]> {
  assertCan(ctx, 'project:read', { orgId: ctx.orgId });

  const rows = await prisma.project.findMany({
    where: { orgId: ctx.orgId },
    orderBy: { createdAt: 'desc' },
    include: { _count: { select: { dependencies: true } } },
  });

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    description: row.description,
    ecosystem: row.ecosystem,
    source: row.source,
    repoUrl: row.repoUrl,
    lastScanAt: row.lastScanAt,
    dependencyCount: row._count.dependencies,
    createdAt: row.createdAt,
  }));
}

export async function get(
  ctx: AuthContext & { actorEmail: string },
  projectId: string,
): Promise<ProjectSummary> {
  assertCan(ctx, 'project:read', { orgId: ctx.orgId });

  const row = await prisma.project.findFirst({
    where: { id: projectId, orgId: ctx.orgId },
    include: { _count: { select: { dependencies: true } } },
  });

  if (!row) throw new NotFoundError('Project not found.');

  return {
    id: row.id,
    name: row.name,
    description: row.description,
    ecosystem: row.ecosystem,
    source: row.source,
    repoUrl: row.repoUrl,
    lastScanAt: row.lastScanAt,
    dependencyCount: row._count.dependencies,
    createdAt: row.createdAt,
  };
}
