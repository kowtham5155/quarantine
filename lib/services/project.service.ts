import { Ecosystem, type Prisma, ProjectSource, ScanStatus, Verdict } from '@prisma/client';
import { z } from 'zod';

import { audit } from '@/lib/audit';
import { VERDICT_META } from '@/lib/constants';
import { prisma } from '@/lib/db';
import { NotFoundError, ValidationError } from '@/lib/errors';
import { MAX_LOCKFILE_BYTES, parseLockfile, type LockfileKind } from '@/lib/lockfile';
import { logger } from '@/lib/logger';
import { assertCan, type AuthContext } from '@/lib/rbac';
import * as analysisService from '@/lib/services/analysis.service';

/**
 * Projects — the org-scoped container a dependency tree is scanned against.
 *
 * A project holds a *graph*, not a scan queue: importing a lockfile records
 * what depends on what, and verdicts are joined in from analyses this org has
 * already run. Queueing work is a separate, explicitly bounded action, because
 * a 900-entry lockfile that silently fanned out into 900 tarball downloads
 * would be a denial of service the user did not ask for.
 *
 * Nothing here reads package contents. The lockfile is parsed as text by a pure
 * parser and never written to disk (THE SAFETY RULE).
 *
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
  /** Cached from the last import; null before a lockfile has been read. */
  risk: ProjectRisk | null;
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
    risk: null,
    createdAt: project.createdAt,
  };
}

export async function listForOrg(ctx: AuthContext): Promise<ProjectSummary[]> {
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
    risk: readRiskSummary(row.riskSummary),
    createdAt: row.createdAt,
  }));
}

export async function get(ctx: AuthContext, projectId: string): Promise<ProjectSummary> {
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
    risk: readRiskSummary(row.riskSummary),
    createdAt: row.createdAt,
  };
}

// ---------------------------------------------------------------------------
// Update and delete
// ---------------------------------------------------------------------------

export const updateProjectSchema = z.object({
  name: z.string().trim().min(2, 'Enter a project name.').max(80),
  description: z.string().trim().max(500).optional(),
  repoUrl: z.string().trim().url('Enter a valid URL.').max(500).optional(),
});

export async function update(
  ctx: AuthContext & { actorEmail: string },
  projectId: string,
  input: z.infer<typeof updateProjectSchema>,
  request: RequestInfo = {},
): Promise<ProjectSummary> {
  assertCan(ctx, 'project:update', { orgId: ctx.orgId });

  const parsed = updateProjectSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const existing = await prisma.project.findFirst({
    where: { id: projectId, orgId: ctx.orgId },
    select: { id: true },
  });
  if (!existing) throw new NotFoundError('Project not found.');

  const clash = await prisma.project.findFirst({
    where: { orgId: ctx.orgId, name: parsed.data.name, NOT: { id: projectId } },
    select: { id: true },
  });
  if (clash) {
    throw new ValidationError('A project with that name already exists.', {
      details: { fieldErrors: { name: ['A project with that name already exists.'] } },
    });
  }

  const row = await prisma.project.update({
    where: { id: existing.id },
    data: {
      name: parsed.data.name,
      description: parsed.data.description ?? null,
      repoUrl: parsed.data.repoUrl ?? null,
    },
    include: { _count: { select: { dependencies: true } } },
  });

  await audit(ctx, 'project.updated', { type: 'Project', id: row.id }, { name: row.name }, request);

  return {
    id: row.id,
    name: row.name,
    description: row.description,
    ecosystem: row.ecosystem,
    source: row.source,
    repoUrl: row.repoUrl,
    lastScanAt: row.lastScanAt,
    dependencyCount: row._count.dependencies,
    risk: readRiskSummary(row.riskSummary),
    createdAt: row.createdAt,
  };
}

export async function remove(
  ctx: AuthContext & { actorEmail: string },
  projectId: string,
  request: RequestInfo = {},
): Promise<void> {
  assertCan(ctx, 'project:delete', { orgId: ctx.orgId });

  const result = await prisma.project.deleteMany({ where: { id: projectId, orgId: ctx.orgId } });
  if (result.count === 0) throw new NotFoundError('Project not found.');

  await audit(ctx, 'project.deleted', { type: 'Project', id: projectId }, {}, request);
}

// ---------------------------------------------------------------------------
// Dependency import
// ---------------------------------------------------------------------------

/** Hard cap on coordinates one import will record. */
export const MAX_PROJECT_DEPENDENCIES = 1500;

export interface ImportResult {
  scanId: string;
  kind: LockfileKind;
  found: number;
  imported: number;
  direct: number;
  truncated: boolean;
}

/**
 * Replace a project's dependency graph from a lockfile.
 *
 * Replace, not merge: a lockfile is a complete statement of what the project
 * resolves to, so a dependency that is gone from the file is gone from the
 * project. Merging would leave removed packages sitting in the tree looking
 * current, which is precisely the failure mode a supply-chain tool cannot have.
 */
export async function importLockfile(
  ctx: AuthContext & { actorEmail: string },
  projectId: string,
  file: { name: string; content: string },
  request: RequestInfo = {},
): Promise<ImportResult> {
  assertCan(ctx, 'project:update', { orgId: ctx.orgId });

  const project = await prisma.project.findFirst({
    where: { id: projectId, orgId: ctx.orgId },
    select: { id: true, ecosystem: true },
  });
  if (!project) throw new NotFoundError('Project not found.');

  if (file.content.length > MAX_LOCKFILE_BYTES) {
    throw new ValidationError('That lockfile is too large to read.', {
      details: {
        fieldErrors: {
          lockfile: [`Lockfiles are limited to ${MAX_LOCKFILE_BYTES / (1024 * 1024)}MB.`],
        },
      },
    });
  }

  const parsed = parseLockfile(file.name, file.content, {
    maxEntries: MAX_PROJECT_DEPENDENCIES,
  });

  if (parsed.kind === 'unknown') {
    throw new ValidationError('That file was not recognised as a package-lock.json or yarn.lock.', {
      details: { fieldErrors: { lockfile: ['Unrecognised lockfile format.'] } },
    });
  }

  if (parsed.entries.length === 0) {
    throw new ValidationError('That lockfile lists no packages we can analyse.', {
      details: { fieldErrors: { lockfile: ['No usable dependencies found.'] } },
    });
  }

  const scan = await prisma.projectScan.create({
    data: {
      orgId: ctx.orgId,
      projectId: project.id,
      status: ScanStatus.RUNNING,
      startedAt: new Date(),
      totalDeps: parsed.entries.length,
    },
    select: { id: true },
  });

  try {
    // The catalogue is global, so these upserts are shared across tenants by
    // design; the tenant-scoped row is the Dependency, which carries projectId.
    const versionIds = new Map<string, string>();

    for (const entry of parsed.entries) {
      const pkg = await prisma.package.upsert({
        where: { ecosystem_name: { ecosystem: project.ecosystem, name: entry.name } },
        create: { ecosystem: project.ecosystem, name: entry.name },
        update: {},
        select: { id: true },
      });

      const version = await prisma.packageVersion.upsert({
        where: { packageId_version: { packageId: pkg.id, version: entry.version } },
        create: { packageId: pkg.id, version: entry.version },
        update: {},
        select: { id: true },
      });

      versionIds.set(`${entry.name}@${entry.version}`, version.id);
    }

    const rows = parsed.entries.flatMap((entry) => {
      const packageVersionId = versionIds.get(`${entry.name}@${entry.version}`);
      if (!packageVersionId) return [];
      return [
        {
          projectId: project.id,
          packageVersionId,
          isDirect: entry.direct,
          depth: entry.depth,
          path: entry.path,
        },
      ];
    });

    await prisma.$transaction([
      prisma.dependency.deleteMany({ where: { projectId: project.id } }),
      // Two entries for the same coordinate at the same depth would collide on
      // the model's unique key; the parser already deduplicates by coordinate.
      prisma.dependency.createMany({ data: rows, skipDuplicates: true }),
      prisma.project.update({
        where: { id: project.id },
        data: { lastScanAt: new Date() },
      }),
    ]);

    const risk = await recomputeRisk(ctx, project.id);

    await prisma.projectScan.update({
      where: { id: scan.id },
      data: {
        status: ScanStatus.COMPLETED,
        completedAt: new Date(),
        totalDeps: rows.length,
        flaggedDeps: risk.flagged,
        blockedDeps: risk.blocked,
        summary: risk as unknown as Prisma.InputJsonValue,
      },
    });

    await audit(
      ctx,
      'project.dependencies_imported',
      { type: 'Project', id: project.id },
      { kind: parsed.kind, imported: rows.length, found: parsed.found },
      request,
    );

    return {
      scanId: scan.id,
      kind: parsed.kind,
      found: parsed.found,
      imported: rows.length,
      direct: rows.filter((row) => row.isDirect).length,
      truncated: parsed.truncated,
    };
  } catch (error) {
    await prisma.projectScan.update({
      where: { id: scan.id },
      data: { status: ScanStatus.FAILED, completedAt: new Date() },
    });
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Reading the graph
// ---------------------------------------------------------------------------

export interface DependencyRow {
  id: string;
  packageVersionId: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  isDirect: boolean;
  depth: number;
  /** Ancestor chain from the root project, excluding this package. */
  path: string[];
  verdict: Verdict | null;
  confidence: number | null;
  analysisId: string | null;
  analysedAt: Date | null;
  /** True when this org holds this coordinate in quarantine. */
  quarantined: boolean;
}

const DEPENDENCY_INCLUDE = (orgId: string) =>
  ({
    packageVersion: {
      include: {
        package: { select: { ecosystem: true, name: true } },
        analyses: {
          where: { orgId, verdict: { not: null } },
          orderBy: { completedAt: 'desc' },
          take: 1,
          select: { id: true, verdict: true, confidence: true, completedAt: true },
        },
        quarantineItems: {
          where: { orgId, state: 'HELD' },
          select: { id: true },
          take: 1,
        },
      },
    },
  }) satisfies Prisma.DependencyInclude;

/** Every dependency of a project with this org's verdict joined in. */
export async function listDependencies(
  ctx: AuthContext,
  projectId: string,
): Promise<DependencyRow[]> {
  assertCan(ctx, 'project:read', { orgId: ctx.orgId });

  const project = await prisma.project.findFirst({
    where: { id: projectId, orgId: ctx.orgId },
    select: { id: true },
  });
  if (!project) throw new NotFoundError('Project not found.');

  const rows = await prisma.dependency.findMany({
    where: { projectId: project.id },
    include: DEPENDENCY_INCLUDE(ctx.orgId),
    orderBy: [{ depth: 'asc' }, { id: 'asc' }],
  });

  return rows
    .map((row) => {
      const analysis = row.packageVersion.analyses[0];
      return {
        id: row.id,
        packageVersionId: row.packageVersionId,
        ecosystem: row.packageVersion.package.ecosystem,
        name: row.packageVersion.package.name,
        version: row.packageVersion.version,
        isDirect: row.isDirect,
        depth: row.depth,
        path: row.path,
        verdict: analysis?.verdict ?? null,
        confidence: analysis?.confidence ?? null,
        analysisId: analysis?.id ?? null,
        analysedAt: analysis?.completedAt ?? null,
        quarantined: row.packageVersion.quarantineItems.length > 0,
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}

export interface DependencyTreeNode extends DependencyRow {
  /** Children of this node in the shortest-path tree. */
  children: DependencyTreeNode[];
  /** Worst verdict anywhere in this subtree, including the node itself. */
  subtreeWorst: Verdict | null;
  subtreeCount: number;
}

function worseOf(a: Verdict | null, b: Verdict | null): Verdict | null {
  if (!a) return b;
  if (!b) return a;
  return VERDICT_META[a].rank <= VERDICT_META[b].rank ? a : b;
}

/**
 * Build the shortest-path tree the flat rows describe.
 *
 * A dependency graph is a DAG, not a tree — the same package is reached by many
 * routes. The stored `path` is the shortest route to it, so rebuilding by that
 * path gives every package exactly one place in the tree, which is what makes
 * the view expandable without rendering the same subtree fifty times.
 */
export function buildTree(rows: readonly DependencyRow[]): DependencyTreeNode[] {
  const nodes = new Map<string, DependencyTreeNode>();
  for (const row of rows) {
    nodes.set(row.name, { ...row, children: [], subtreeWorst: row.verdict, subtreeCount: 1 });
  }

  const roots: DependencyTreeNode[] = [];

  for (const row of rows) {
    const node = nodes.get(row.name);
    if (!node) continue;

    const parentName = row.path.at(-1);
    const parent = parentName ? nodes.get(parentName) : undefined;

    // A node whose recorded parent is not in this project (a lockfile that was
    // truncated at the cap) is attached at the root rather than dropped.
    if (parent && parent !== node) parent.children.push(node);
    else roots.push(node);
  }

  const rollUp = (node: DependencyTreeNode, seen: Set<string>): void => {
    if (seen.has(node.name)) return;
    seen.add(node.name);

    for (const child of node.children) {
      rollUp(child, seen);
      node.subtreeWorst = worseOf(node.subtreeWorst, child.subtreeWorst);
      node.subtreeCount += child.subtreeCount;
    }

    node.children.sort((a, b) => a.name.localeCompare(b.name));
  };

  for (const root of roots) rollUp(root, new Set());
  roots.sort((a, b) => a.name.localeCompare(b.name));

  return roots;
}

export interface ProjectRisk {
  total: number;
  direct: number;
  transitive: number;
  analysed: number;
  unanalysed: number;
  flagged: number;
  blocked: number;
  worstVerdict: Verdict | null;
  byVerdict: Record<Verdict, number>;
}

function emptyRisk(): ProjectRisk {
  return {
    total: 0,
    direct: 0,
    transitive: 0,
    analysed: 0,
    unanalysed: 0,
    flagged: 0,
    blocked: 0,
    worstVerdict: null,
    byVerdict: {
      [Verdict.CLEAN]: 0,
      [Verdict.LOW_RISK]: 0,
      [Verdict.SUSPICIOUS]: 0,
      [Verdict.LIKELY_MALICIOUS]: 0,
      [Verdict.KNOWN_MALICIOUS]: 0,
    },
  };
}

export function summariseRisk(rows: readonly DependencyRow[]): ProjectRisk {
  const risk = emptyRisk();

  for (const row of rows) {
    risk.total += 1;
    if (row.isDirect) risk.direct += 1;
    else risk.transitive += 1;

    if (row.quarantined) risk.blocked += 1;

    if (!row.verdict) {
      risk.unanalysed += 1;
      continue;
    }

    risk.analysed += 1;
    risk.byVerdict[row.verdict] += 1;
    risk.worstVerdict = worseOf(risk.worstVerdict, row.verdict);

    if (
      row.verdict === Verdict.SUSPICIOUS ||
      row.verdict === Verdict.LIKELY_MALICIOUS ||
      row.verdict === Verdict.KNOWN_MALICIOUS
    ) {
      risk.flagged += 1;
    }
  }

  return risk;
}

/** Recompute and persist the cached risk summary the project list renders. */
export async function recomputeRisk(ctx: AuthContext, projectId: string): Promise<ProjectRisk> {
  const rows = await listDependencies(ctx, projectId);
  const risk = summariseRisk(rows);

  await prisma.project.updateMany({
    where: { id: projectId, orgId: ctx.orgId },
    data: { riskSummary: risk as unknown as Prisma.InputJsonValue },
  });

  return risk;
}

/** Read the cached summary, tolerating a row that predates the current shape. */
export function readRiskSummary(value: Prisma.JsonValue): ProjectRisk | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (typeof record.total !== 'number') return null;

  const base = emptyRisk();
  const byVerdict = { ...base.byVerdict };

  if (record.byVerdict && typeof record.byVerdict === 'object') {
    for (const [key, count] of Object.entries(record.byVerdict as Record<string, unknown>)) {
      if (key in byVerdict && typeof count === 'number') byVerdict[key as Verdict] = count;
    }
  }

  const number = (key: string): number =>
    typeof record[key] === 'number' ? (record[key] as number) : 0;

  const worst = record.worstVerdict;

  return {
    total: number('total'),
    direct: number('direct'),
    transitive: number('transitive'),
    analysed: number('analysed'),
    unanalysed: number('unanalysed'),
    flagged: number('flagged'),
    blocked: number('blocked'),
    worstVerdict: typeof worst === 'string' && worst in byVerdict ? (worst as Verdict) : null,
    byVerdict,
  };
}

// ---------------------------------------------------------------------------
// Queueing analyses for a project
// ---------------------------------------------------------------------------

/** How many coordinates one "scan dependencies" action may queue. */
export const PROJECT_QUEUE_LIMIT = 50;

export interface QueueOutcome {
  queued: number;
  skipped: number;
  remaining: number;
}

/**
 * Queue analyses for the project's unanalysed dependencies, newest-first by
 * depth so direct dependencies are covered before their transitive tail.
 *
 * Bounded on purpose. The remaining count is returned so the page can say how
 * much is left rather than pretending the project is fully covered.
 */
export async function queueDependencyAnalyses(
  ctx: AuthContext & { actorEmail: string },
  projectId: string,
  request: RequestInfo = {},
): Promise<QueueOutcome> {
  assertCan(ctx, 'analysis:create', { orgId: ctx.orgId });

  const rows = await listDependencies(ctx, projectId);
  const pending = rows
    .filter((row) => row.verdict === null)
    .sort((a, b) => a.depth - b.depth || a.name.localeCompare(b.name));

  const batch = pending.slice(0, PROJECT_QUEUE_LIMIT);
  let queued = 0;
  let skipped = 0;

  for (const row of batch) {
    try {
      await analysisService.queueAnalysis(
        ctx,
        { ecosystem: row.ecosystem, name: row.name, version: row.version },
        request,
      );
      queued += 1;
    } catch (error) {
      // A coordinate the registry would reject must not sink the batch.
      logger.debug({ err: error, name: row.name }, 'dependency could not be queued');
      skipped += 1;
    }
  }

  return { queued, skipped, remaining: Math.max(pending.length - batch.length, 0) };
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

export interface ScanHistoryPoint {
  id: string;
  status: ScanStatus;
  startedAt: Date | null;
  completedAt: Date | null;
  totalDeps: number;
  flaggedDeps: number;
  blockedDeps: number;
}

export async function listScans(
  ctx: AuthContext,
  projectId: string,
  take = 50,
): Promise<ScanHistoryPoint[]> {
  assertCan(ctx, 'scan:read', { orgId: ctx.orgId });

  const rows = await prisma.projectScan.findMany({
    where: { orgId: ctx.orgId, projectId },
    orderBy: { createdAt: 'desc' },
    take: Math.min(Math.max(take, 1), 200),
    select: {
      id: true,
      status: true,
      startedAt: true,
      completedAt: true,
      totalDeps: true,
      flaggedDeps: true,
      blockedDeps: true,
    },
  });

  return rows;
}

// ---------------------------------------------------------------------------
// SBOM
// ---------------------------------------------------------------------------

export interface SbomDocument {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  serialNumber: string;
  version: number;
  metadata: Record<string, unknown>;
  components: Array<Record<string, unknown>>;
}

/** `pkg:npm/%40scope%2Fname@1.0.0` — package URL, per the purl spec. */
export function purlFor(ecosystem: Ecosystem, name: string, version: string): string {
  const type = ecosystem === Ecosystem.NPM ? 'npm' : 'pypi';
  const encodedName = name
    .split('/')
    .map((segment) => encodeURIComponent(segment))
    .join('/');
  return `pkg:${type}/${encodedName}@${encodeURIComponent(version)}`;
}

/**
 * CycloneDX 1.5 for the project's dependency graph.
 *
 * Verdicts ride along as component properties under a `quarantine:` namespace
 * rather than being forced into a CycloneDX field that means something else —
 * a consumer that does not know this tool still gets a valid, useful SBOM.
 */
export async function buildSbom(
  ctx: AuthContext,
  projectId: string,
): Promise<{ project: ProjectSummary; document: SbomDocument }> {
  const project = await get(ctx, projectId);
  const rows = await listDependencies(ctx, projectId);

  const components = rows.map((row) => ({
    type: 'library',
    'bom-ref': purlFor(row.ecosystem, row.name, row.version),
    name: row.name,
    version: row.version,
    purl: purlFor(row.ecosystem, row.name, row.version),
    scope: row.isDirect ? 'required' : 'optional',
    properties: [
      { name: 'quarantine:verdict', value: row.verdict ?? 'NOT_ANALYSED' },
      { name: 'quarantine:depth', value: String(row.depth) },
      { name: 'quarantine:direct', value: String(row.isDirect) },
      ...(row.confidence === null
        ? []
        : [{ name: 'quarantine:confidence', value: row.confidence.toFixed(2) }]),
      ...(row.quarantined ? [{ name: 'quarantine:held', value: 'true' }] : []),
    ],
  }));

  return {
    project,
    document: {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      // Deterministic: the same project exports the same serial number, so two
      // SBOMs of the same project diff cleanly.
      serialNumber: `urn:uuid:${projectUuid(project.id)}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: {
          components: [
            {
              type: 'application',
              name: 'quarantine',
              version: analysisService.ENGINE_VERSION,
            },
          ],
        },
        component: {
          type: 'application',
          'bom-ref': `project:${project.id}`,
          name: project.name,
          ...(project.description ? { description: project.description } : {}),
        },
      },
      components,
    },
  };
}

/** A stable RFC-4122-shaped identifier derived from the project id. */
function projectUuid(projectId: string): string {
  let hash = 0x811c9dc5;
  for (const char of projectId) {
    hash ^= char.charCodeAt(0);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }

  const hex = hash.toString(16).padStart(8, '0');
  const tail = projectId.replace(/[^0-9a-f]/gi, '0').padEnd(20, '0').slice(0, 20);

  return `${hex}-${tail.slice(0, 4)}-4${tail.slice(4, 7)}-8${tail.slice(7, 10)}-${tail.slice(10, 22).padEnd(12, '0')}`;
}
