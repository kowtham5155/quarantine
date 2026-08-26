import { AnalysisStatus, Ecosystem, Severity, type Prisma } from '@prisma/client';
import { z } from 'zod';

import { audit } from '@/lib/audit';
import { prisma } from '@/lib/db';
import { AnalysisError, NotFoundError, ValidationError } from '@/lib/errors';
import { logger } from '@/lib/logger';
import { assertCan, Role, type AuthContext } from '@/lib/rbac';
import { analyse, type ProgressEvent } from '@/lib/engine';
import * as npmRegistry from '@/lib/engine/registry/npm';
import { isValidNpmName, isValidVersion } from '@/lib/engine/registry/npm';
import * as pypiRegistry from '@/lib/engine/registry/pypi';
import { isValidPypiName } from '@/lib/engine/registry/pypi';
import type { AnalysisResult, RuleDefinition, Signal } from '@/lib/engine/types';
import { applyPolicies } from '@/lib/services/policy.service';
import { clusterAnalysis } from '@/lib/services/campaign.service';

/**
 * Analysis service: queue, run, read, compare.
 *
 * The engine itself is pure — it takes a package coordinate and returns a
 * result. This service is what gives it a home: it owns the Analysis row, the
 * rule catalogue it feeds the engine, persistence of signal hits, and tenant
 * isolation. Every query filters on `ctx.orgId` (CLAUDE.md rule 4).
 *
 * ## Execution model
 *
 * There is no persistent worker on the deployment target, so an analysis runs
 * inline in the request that asks for it, streaming progress as it goes. The
 * cron endpoint sweeps anything left QUEUED. Both paths call `runAnalysis`, so
 * there is exactly one implementation of "run this and record what happened".
 */

export const ENGINE_VERSION = '1.0.0';

export interface RequestInfo {
  ip?: string | null;
  userAgent?: string | null;
}

// ---------------------------------------------------------------------------
// Rule catalogue
// ---------------------------------------------------------------------------

/**
 * Load the rule catalogue the engine scores against.
 *
 * Read from the database rather than from the seed file so that weight tuning
 * and rule disabling take effect without a deploy — which is the whole point of
 * the rules table.
 */
export async function loadRuleCatalogue(): Promise<Map<string, RuleDefinition>> {
  const rules = await prisma.rule.findMany({
    select: {
      ruleId: true,
      family: true,
      name: true,
      description: true,
      severity: true,
      baseWeight: true,
      enabled: true,
    },
  });

  return new Map(rules.map((rule) => [rule.ruleId, rule]));
}

/** Tarball hashes already confirmed malicious, for the KNOWN_MALICIOUS path. */
export async function loadKnownBadHashes(): Promise<Set<string>> {
  const entries = await prisma.corpusEntry.findMany({
    where: { label: 'MALICIOUS', tarballSha256: { not: null } },
    select: { tarballSha256: true },
  });

  const hashes = new Set<string>();
  for (const entry of entries) {
    if (entry.tarballSha256) hashes.add(entry.tarballSha256);
  }
  return hashes;
}

// ---------------------------------------------------------------------------
// Version resolution
// ---------------------------------------------------------------------------

/**
 * Turn what a human typed into a concrete version.
 *
 * `lodash`, `lodash@latest` and `lodash@^4` all have to become an exact version
 * before an Analysis row exists, because a verdict is a statement about one
 * artefact and a range is not an artefact. npm dist-tags are resolved against
 * the packument; PyPI has no tags, so its own idea of the current release is
 * used. A range that is not a tag is rejected rather than guessed at.
 */
export async function resolveVersion(
  ecosystem: Ecosystem,
  name: string,
  requested?: string | null,
): Promise<string> {
  const wanted = (requested ?? '').trim();

  if (ecosystem === Ecosystem.NPM) {
    if (wanted && isValidVersion(wanted) && !/^[~^><=*]/.test(wanted) && /^\d/.test(wanted)) {
      return wanted;
    }

    const packument = await npmRegistry.fetchPackument(name);
    const tag = wanted || 'latest';
    const resolved = packument['dist-tags']?.[tag];

    if (resolved) return resolved;
    if (wanted && packument.versions?.[wanted]) return wanted;

    throw new ValidationError(
      wanted
        ? 'That version or dist-tag was not found in the registry.'
        : 'The registry lists no current version for that package.',
      { details: { fieldErrors: { version: ['Not found in the registry.'] } } },
    );
  }

  const document = await pypiRegistry.fetchPypiDocument(name);
  if (wanted) {
    if (document.releases && Object.hasOwn(document.releases, wanted)) return wanted;
    throw new ValidationError('That version was not found on PyPI.', {
      details: { fieldErrors: { version: ['Not found in the registry.'] } },
    });
  }

  const latest = document.info?.version;
  if (typeof latest === 'string' && latest.length > 0) return latest;

  throw new ValidationError('PyPI lists no current version for that package.');
}

// ---------------------------------------------------------------------------
// Queue
// ---------------------------------------------------------------------------

export const queueAnalysisSchema = z.object({
  ecosystem: z.nativeEnum(Ecosystem),
  name: z.string().trim().min(1).max(214),
  version: z.string().trim().min(1).max(64),
});

export type QueueAnalysisInput = z.infer<typeof queueAnalysisSchema>;

export interface QueuedAnalysis {
  analysisId: string;
  status: AnalysisStatus;
  /** True when an existing completed analysis was returned instead of a new one. */
  reused: boolean;
}

/**
 * Register a package version and queue an analysis for it.
 *
 * Idempotent within a short window: asking twice for the same coordinate while
 * one is already queued or running returns the existing analysis rather than
 * starting a second download of the same tarball.
 */
export async function queueAnalysis(
  ctx: AuthContext & { actorEmail: string },
  input: QueueAnalysisInput,
  request: RequestInfo = {},
): Promise<QueuedAnalysis> {
  assertCan(ctx, 'scan:create', { orgId: ctx.orgId });

  const parsed = queueAnalysisSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const { ecosystem, name, version } = parsed.data;

  const validName = ecosystem === Ecosystem.NPM ? isValidNpmName(name) : isValidPypiName(name);
  if (!validName) {
    throw new ValidationError('That is not a valid package name for this ecosystem.', {
      details: { fieldErrors: { name: ['Not a valid package name.'] } },
    });
  }
  if (!isValidVersion(version)) {
    throw new ValidationError('That is not a valid version string.', {
      details: { fieldErrors: { version: ['Not a valid version.'] } },
    });
  }

  const packageVersion = await upsertPackageVersion(ecosystem, name, version);

  // Reuse anything already in flight for this coordinate in this org.
  const inFlight = await prisma.analysis.findFirst({
    where: {
      orgId: ctx.orgId,
      packageVersionId: packageVersion.id,
      status: { in: [AnalysisStatus.QUEUED, AnalysisStatus.RUNNING] },
    },
    orderBy: { createdAt: 'desc' },
    select: { id: true, status: true },
  });

  if (inFlight) {
    return { analysisId: inFlight.id, status: inFlight.status, reused: true };
  }

  const analysis = await prisma.analysis.create({
    data: {
      orgId: ctx.orgId,
      packageVersionId: packageVersion.id,
      status: AnalysisStatus.QUEUED,
      engineVersion: ENGINE_VERSION,
    },
    select: { id: true, status: true },
  });

  await audit(
    ctx,
    'scan.created',
    { type: 'Analysis', id: analysis.id },
    { ecosystem, name, version },
    request,
  );

  return { analysisId: analysis.id, status: analysis.status, reused: false };
}

/** Create or fetch the Package and PackageVersion rows. Global, not org-scoped. */
async function upsertPackageVersion(
  ecosystem: Ecosystem,
  name: string,
  version: string,
): Promise<{ id: string }> {
  const pkg = await prisma.package.upsert({
    where: { ecosystem_name: { ecosystem, name } },
    create: { ecosystem, name },
    update: {},
    select: { id: true },
  });

  return prisma.packageVersion.upsert({
    where: { packageId_version: { packageId: pkg.id, version } },
    create: { packageId: pkg.id, version },
    update: {},
    select: { id: true },
  });
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

export interface RunOptions {
  onProgress?: (event: ProgressEvent) => void;
  budgetMs?: number;
}

export interface RunnableAnalysis {
  analysisId: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  status: AnalysisStatus;
}

/**
 * Check that an analysis exists, belongs to the caller's org, and is in a state
 * that can be run — without starting it.
 *
 * The streaming endpoint needs this. Once a response body has started, the
 * status code is already committed, so "no such analysis" would have to be
 * reported as a 200 containing an error line. Doing the cheap checks first lets
 * the ordinary failures come back as ordinary HTTP errors. The race it leaves
 * open — a status that changes between this call and the claim — is closed by
 * the conditional `updateMany` in `runAnalysis`, which is the real guard.
 */
export async function assertAnalysisRunnable(
  ctx: AuthContext,
  analysisId: string,
): Promise<RunnableAnalysis> {
  assertCan(ctx, 'scan:create', { orgId: ctx.orgId });

  const analysis = await prisma.analysis.findFirst({
    where: { id: analysisId, orgId: ctx.orgId },
    select: {
      id: true,
      status: true,
      packageVersion: {
        select: { version: true, package: { select: { name: true, ecosystem: true } } },
      },
    },
  });

  if (!analysis) throw new NotFoundError('Analysis not found.');

  if (analysis.status === AnalysisStatus.RUNNING) {
    throw new ValidationError('That analysis is already running.');
  }
  if (analysis.status === AnalysisStatus.COMPLETED) {
    throw new ValidationError(
      'That analysis has already completed. Queue a new scan to analyse it again.',
    );
  }

  return {
    analysisId: analysis.id,
    ecosystem: analysis.packageVersion.package.ecosystem,
    name: analysis.packageVersion.package.name,
    version: analysis.packageVersion.version,
    status: analysis.status,
  };
}

/**
 * Run a queued analysis to completion and persist everything it found.
 *
 * A failed engine run is recorded as FAILED with a message, not thrown: the
 * caller asked to run an analysis, and "it ran and could not reach the
 * registry" is a result. Genuine programming errors still surface, because they
 * are logged as non-operational.
 */
export async function runAnalysis(
  ctx: AuthContext & { actorEmail: string },
  analysisId: string,
  options: RunOptions = {},
): Promise<AnalysisResult | null> {
  assertCan(ctx, 'scan:create', { orgId: ctx.orgId });

  const analysis = await prisma.analysis.findFirst({
    where: { id: analysisId, orgId: ctx.orgId },
    include: {
      packageVersion: { include: { package: true } },
    },
  });

  if (!analysis) throw new NotFoundError('Analysis not found.');

  if (analysis.status === AnalysisStatus.RUNNING) {
    throw new ValidationError('That analysis is already running.');
  }
  if (analysis.status === AnalysisStatus.COMPLETED) {
    throw new ValidationError(
      'That analysis has already completed. Queue a new scan to analyse it again.',
    );
  }

  const { packageVersion } = analysis;
  const { package: pkg } = packageVersion;

  // Claim the row. `updateMany` with a status guard means two concurrent
  // requests cannot both start the same analysis.
  const claimed = await prisma.analysis.updateMany({
    where: {
      id: analysis.id,
      orgId: ctx.orgId,
      status: { in: [AnalysisStatus.QUEUED, AnalysisStatus.FAILED, AnalysisStatus.PARTIAL] },
    },
    data: { status: AnalysisStatus.RUNNING, startedAt: new Date(), errorMessage: null },
  });

  if (claimed.count === 0) {
    throw new ValidationError('That analysis is already running.');
  }

  const [rules, knownBadHashes] = await Promise.all([loadRuleCatalogue(), loadKnownBadHashes()]);

  try {
    const result = await analyse({
      ecosystem: pkg.ecosystem,
      name: pkg.name,
      version: packageVersion.version,
      rules,
      knownBadHashes,
      ...(options.budgetMs === undefined ? {} : { budgetMs: options.budgetMs }),
      ...(options.onProgress ? { onProgress: options.onProgress } : {}),
      correlationId: analysis.id,
    });

    await persistResult(ctx, analysis.id, packageVersion.id, pkg.id, result, rules);

    // Clustering is best-effort: a campaign that fails to form must not fail
    // the analysis that produced the evidence.
    try {
      await clusterAnalysis(ctx, analysis.id);
    } catch (error) {
      logger.warn({ err: error, analysisId: analysis.id }, 'campaign clustering failed');
    }

    // Policy enforcement, on the same terms. The evidence is already durable at
    // this point; a policy that cannot be evaluated is a governance gap to
    // report, not a reason to discard an analysis that succeeded.
    try {
      await applyPolicies(ctx, analysis.id);
    } catch (error) {
      logger.warn({ err: error, analysisId: analysis.id }, 'policy enforcement failed');
    }

    return result;
  } catch (error) {
    const message =
      error instanceof AnalysisError
        ? error.message
        : 'The analysis could not be completed. The registry may be unavailable.';

    logger.error({ err: error, analysisId: analysis.id }, 'analysis failed');

    await prisma.analysis.updateMany({
      where: { id: analysis.id, orgId: ctx.orgId },
      data: {
        status: AnalysisStatus.FAILED,
        completedAt: new Date(),
        errorMessage: message,
      },
    });

    return null;
  }
}

/** Write the engine's output into the Analysis row and its child tables. */
async function persistResult(
  ctx: AuthContext,
  analysisId: string,
  packageVersionId: string,
  packageId: string,
  result: AnalysisResult,
  rules: Map<string, RuleDefinition>,
): Promise<void> {
  const fired = result.signals.filter((signal) => signal.fired);

  const signalCounts: Record<string, number> = {};
  for (const signal of fired) {
    signalCounts[signal.family] = (signalCounts[signal.family] ?? 0) + 1;
  }

  await prisma.$transaction(async (tx) => {
    // Replacing rather than appending: a re-run supersedes its predecessor.
    await tx.signalHit.deleteMany({ where: { analysisId } });
    await tx.provenanceCheck.deleteMany({ where: { analysisId } });
    await tx.typosquatMatch.deleteMany({ where: { analysisId } });

    await tx.analysis.update({
      where: { id: analysisId },
      data: {
        status: result.partial ? AnalysisStatus.PARTIAL : AnalysisStatus.COMPLETED,
        verdict: result.verdict,
        confidence: result.confidence,
        weightedScore: result.weightedScore,
        hardTriggersFired: result.hardTriggers.map((trigger) => trigger.id),
        completedAt: new Date(),
        durationMs: result.durationMs,
        engineVersion: ENGINE_VERSION,
        signalCounts: signalCounts as Prisma.InputJsonValue,
        filesAnalysed: result.signals.length > 0 ? countFiles(result.signals) : 0,
      },
    });

    if (fired.length > 0) {
      await tx.signalHit.createMany({
        data: fired.flatMap((signal) => toSignalHitRows(analysisId, signal, rules)),
      });
    }

    const provenance = toProvenanceRow(analysisId, result);
    if (provenance) await tx.provenanceCheck.create({ data: provenance });

    const typosquats = toTyposquatRows(analysisId, result);
    if (typosquats.length > 0) await tx.typosquatMatch.createMany({ data: typosquats });

    // Registry facts, written back so the catalogue survives the scan directory
    // being deleted. Policy conditions (package age, maintainer count, licence)
    // read these columns, so they have to be persisted rather than recomputed
    // from a tarball nobody keeps.
    const facts = result.catalogue;

    await tx.packageVersion.update({
      where: { id: packageVersionId },
      data: {
        hasInstallScripts: fired.some((signal) => signal.ruleId === 'Q-INS-001'),
        fileCount: countFiles(result.signals),
        unpackedSize: facts.unpackedSize,
        provenanceAttested: facts.hasProvenanceAttestation,
        ...(facts.publishedAt ? { publishedAt: facts.publishedAt } : {}),
        ...(facts.tarballUrl ? { tarballUrl: facts.tarballUrl } : {}),
        ...(facts.integrity ? { integrity: facts.integrity } : {}),
      },
    });

    await tx.package.update({
      where: { id: packageId },
      data: {
        latestVersion: result.version,
        description: facts.description,
        license: facts.license,
        repositoryUrl: facts.repositoryUrl,
        maintainerCount: facts.maintainerCount,
        ...(facts.weeklyDownloads === null ? {} : { weeklyDownloads: facts.weeklyDownloads }),
        ...(facts.firstPublishedAt ? { firstPublishedAt: facts.firstPublishedAt } : {}),
      },
    });
  });

  logger.info(
    {
      analysisId,
      orgId: ctx.orgId,
      verdict: result.verdict,
      score: Number(result.weightedScore.toFixed(2)),
      partial: result.partial,
    },
    'analysis completed',
  );
}

/** Distinct files mentioned in any evidence, as a rough "files analysed" count. */
function countFiles(signals: Signal[]): number {
  const files = new Set<string>();
  for (const signal of signals) {
    for (const item of signal.evidence) {
      if (item.file) files.add(item.file);
    }
  }
  return files.size;
}

/** One SignalHit row per piece of evidence, or one bare row when there is none. */
function toSignalHitRows(
  analysisId: string,
  signal: Signal,
  rules: Map<string, RuleDefinition>,
): Prisma.SignalHitCreateManyInput[] {
  const rule = rules.get(signal.ruleId);
  const base = {
    analysisId,
    ruleId: signal.ruleId,
    family: signal.family,
    severity: rule?.severity ?? Severity.MEDIUM,
    weight: rule?.baseWeight ?? 0,
    confidence: signal.confidence,
    contextModifier: signal.contextModifier,
  };

  if (signal.evidence.length === 0) {
    return [{ ...base, evidence: {} as Prisma.InputJsonValue }];
  }

  // Evidence is already capped at 25 per signal by the builder.
  return signal.evidence.map((item) => ({
    ...base,
    filePath: item.file ?? null,
    lineStart: item.startLine ?? null,
    lineEnd: item.endLine ?? null,
    // HOSTILE INPUT: verbatim package content. Stored as-is and escaped on
    // render; never interpolated anywhere.
    excerpt: item.excerpt ?? null,
    evidence: (item.detail ?? {}) as Prisma.InputJsonValue,
  }));
}

function toProvenanceRow(
  analysisId: string,
  result: AnalysisResult,
): Prisma.ProvenanceCheckCreateInput | null {
  const provenanceSignals = result.signals.filter((signal) => signal.family === 'PROVENANCE');
  if (provenanceSignals.length === 0) return null;

  const noRepo = provenanceSignals.find((s) => s.ruleId === 'Q-PRV-001')?.fired;

  // Q-PRV-002 covers two different facts: the repository could not be read, and
  // the repository is archived while the package still publishes. Only the
  // first one stops the comparison. Reporting an archived repository as
  // REPO_UNREACHABLE threw away a completed diff — left-pad@1.3.0 compared
  // clean against an archived repo and still displayed as unchecked.
  const repoSignal = provenanceSignals.find((s) => s.ruleId === 'Q-PRV-002');
  const comparisonRan = provenanceSignals.some(
    (s) => (s.ruleId === 'Q-PRV-003' || s.ruleId === 'Q-PRV-004') && s.skipped === undefined,
  );
  const unreachable = repoSignal?.fired === true && !comparisonRan;
  const extras = provenanceSignals.find((s) => s.ruleId === 'Q-PRV-003');
  const modified = provenanceSignals.find((s) => s.ruleId === 'Q-PRV-004');

  // A comparison that could not conclude must not be recorded as a clean one.
  // Built output differs from its source tree by construction, so DIVERGENT is
  // the truthful status; `diffSummary.unverifiable` is what lets the report say
  // why, rather than implying the difference is suspicious.
  const builtOutput = extras?.skipped === 'BUILD_OUTPUT';

  const status = noRepo
    ? 'NO_REPO'
    : unreachable
      ? 'REPO_UNREACHABLE'
      : extras?.skipped === 'NO_TAG_MATCH' || modified?.skipped === 'NO_TAG_MATCH'
        ? 'NO_TAG'
        : builtOutput || extras?.fired || modified?.fired
          ? 'DIVERGENT'
          : 'MATCH';

  return {
    analysis: { connect: { id: analysisId } },
    status,
    // Null unless the comparison actually ran: naming a tag we never fetched
    // would make a REPO_UNREACHABLE row look like a checked one.
    repoUrl: result.comparedRef?.repositoryUrl ?? result.catalogue.repositoryUrl,
    gitRef: result.comparedRef?.tag ?? null,
    filesOnlyInTarball: (extras?.evidence ?? [])
      .map((item) => item.file)
      .filter((path): path is string => Boolean(path))
      .slice(0, 100),
    modifiedFiles: (modified?.evidence ?? [])
      .map((item) => item.file)
      .filter((path): path is string => Boolean(path))
      .slice(0, 100),
    diffSummary: {
      extraFiles: extras?.evidence.length ?? 0,
      modifiedFiles: modified?.evidence.length ?? 0,
      ...(result.comparedRef ? { filesInRepo: result.comparedRef.filesInRepo } : {}),
      ...(builtOutput ? { unverifiable: 'BUILD_OUTPUT' } : {}),
    } as Prisma.InputJsonValue,
  };
}

function toTyposquatRows(
  analysisId: string,
  result: AnalysisResult,
): Prisma.TyposquatMatchCreateManyInput[] {
  const rows: Prisma.TyposquatMatchCreateManyInput[] = [];

  for (const signal of result.signals) {
    if (signal.family !== 'TYPOSQUAT' || !signal.fired) continue;

    for (const item of signal.evidence) {
      const target = item.detail?.target;
      if (typeof target !== 'string') continue;

      const distance = typeof item.detail?.distance === 'number' ? item.detail.distance : 0;
      const downloads =
        typeof item.detail?.targetWeeklyDownloads === 'number'
          ? item.detail.targetWeeklyDownloads
          : 0;

      rows.push({
        analysisId,
        targetPackage: target,
        distance,
        technique:
          typeof item.detail?.technique === 'string' ? item.detail.technique : signal.ruleId,
        similarity: distance === 0 ? 1 : Math.max(0, 1 - distance / Math.max(1, target.length)),
        targetDownloads: downloads,
      });
    }
  }

  // The same target can be reported by several rules; keep the closest.
  const byTarget = new Map<string, Prisma.TyposquatMatchCreateManyInput>();
  for (const row of rows) {
    const existing = byTarget.get(row.targetPackage);
    if (!existing || row.distance < existing.distance) byTarget.set(row.targetPackage, row);
  }

  return [...byTarget.values()];
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

export async function getAnalysis(ctx: AuthContext & { actorEmail: string }, analysisId: string) {
  assertCan(ctx, 'scan:read', { orgId: ctx.orgId });

  const analysis = await prisma.analysis.findFirst({
    where: { id: analysisId, orgId: ctx.orgId },
    include: {
      packageVersion: { include: { package: true } },
      signalHits: { orderBy: [{ weight: 'desc' }, { ruleId: 'asc' }] },
      provenanceChecks: true,
      typosquatMatches: { orderBy: { distance: 'asc' } },
    },
  });

  if (!analysis) throw new NotFoundError('Analysis not found.');
  return analysis;
}

export const listAnalysesSchema = z.object({
  verdict: z.string().optional(),
  status: z.nativeEnum(AnalysisStatus).optional(),
  ecosystem: z.nativeEnum(Ecosystem).optional(),
  take: z.number().int().min(1).max(100).default(25),
  skip: z.number().int().min(0).default(0),
});

export async function listAnalyses(
  ctx: AuthContext & { actorEmail: string },
  input: Partial<z.infer<typeof listAnalysesSchema>> = {},
) {
  assertCan(ctx, 'scan:read', { orgId: ctx.orgId });

  const parsed = listAnalysesSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const { verdict, status, ecosystem, take, skip } = parsed.data;

  const where: Prisma.AnalysisWhereInput = {
    orgId: ctx.orgId,
    ...(status ? { status } : {}),
    ...(verdict ? { verdict: verdict as Prisma.AnalysisWhereInput['verdict'] } : {}),
    ...(ecosystem ? { packageVersion: { package: { ecosystem } } } : {}),
  };

  const [items, total] = await Promise.all([
    prisma.analysis.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take,
      skip,
      include: { packageVersion: { include: { package: true } } },
    }),
    prisma.analysis.count({ where }),
  ]);

  return { items, total, take, skip };
}

// ---------------------------------------------------------------------------
// Compare
// ---------------------------------------------------------------------------

export interface VersionComparison {
  from: { version: string; verdict: string | null; score: number | null };
  to: { version: string; verdict: string | null; score: number | null };
  /** Rules that fired in `to` but not in `from`. */
  newSignals: string[];
  /** Rules that fired in `from` but not in `to`. */
  resolvedSignals: string[];
  scoreDelta: number;
}

/**
 * Compare two analysed versions of the same package.
 *
 * The interesting output is `newSignals`: what a version added. That is the
 * question a developer bumping a dependency actually has.
 */
export async function compareVersions(
  ctx: AuthContext & { actorEmail: string },
  ecosystem: Ecosystem,
  name: string,
  fromVersion: string,
  toVersion: string,
): Promise<VersionComparison> {
  assertCan(ctx, 'scan:read', { orgId: ctx.orgId });

  const [from, to] = await Promise.all([
    latestAnalysisFor(ctx.orgId, ecosystem, name, fromVersion),
    latestAnalysisFor(ctx.orgId, ecosystem, name, toVersion),
  ]);

  if (!from || !to) {
    throw new NotFoundError('Both versions must have been analysed before they can be compared.');
  }

  const fromRules = new Set(from.signalHits.map((hit) => hit.ruleId));
  const toRules = new Set(to.signalHits.map((hit) => hit.ruleId));

  return {
    from: { version: fromVersion, verdict: from.verdict, score: from.weightedScore },
    to: { version: toVersion, verdict: to.verdict, score: to.weightedScore },
    newSignals: [...toRules].filter((ruleId) => !fromRules.has(ruleId)).sort(),
    resolvedSignals: [...fromRules].filter((ruleId) => !toRules.has(ruleId)).sort(),
    scoreDelta: (to.weightedScore ?? 0) - (from.weightedScore ?? 0),
  };
}

async function latestAnalysisFor(
  orgId: string,
  ecosystem: Ecosystem,
  name: string,
  version: string,
) {
  return prisma.analysis.findFirst({
    where: {
      orgId,
      packageVersion: { version, package: { ecosystem, name } },
      status: { in: [AnalysisStatus.COMPLETED, AnalysisStatus.PARTIAL] },
    },
    orderBy: { completedAt: 'desc' },
    include: { signalHits: { select: { ruleId: true } } },
  });
}

// ---------------------------------------------------------------------------
// Cron support
// ---------------------------------------------------------------------------

/** Queued analyses across every org, oldest first. Used only by the cron sweep. */
export async function claimQueuedAnalyses(
  limit: number,
): Promise<Array<{ id: string; orgId: string }>> {
  return prisma.analysis.findMany({
    where: { status: AnalysisStatus.QUEUED },
    orderBy: { createdAt: 'asc' },
    take: limit,
    select: { id: true, orgId: true },
  });
}

/**
 * Release analyses left RUNNING by a process that died mid-scan.
 *
 * `runAnalysis` claims a row by moving it to RUNNING, and only ever moves it
 * out again in its own try/catch. If the process is killed between those two
 * points — a deploy, an OOM, a platform restart — the row is stranded: it is no
 * longer running anywhere, and the claim guard will refuse to start it again.
 * Anything older than the whole-analysis budget by a wide margin is therefore
 * not slow, it is dead, and it is failed so it can be retried.
 */
export async function reclaimStalledAnalyses(olderThanMs: number): Promise<number> {
  const cutoff = new Date(Date.now() - olderThanMs);

  const { count } = await prisma.analysis.updateMany({
    where: {
      status: AnalysisStatus.RUNNING,
      OR: [{ startedAt: { lt: cutoff } }, { startedAt: null, updatedAt: { lt: cutoff } }],
    },
    data: {
      status: AnalysisStatus.FAILED,
      completedAt: new Date(),
      errorMessage: 'The analysis did not finish. It can be run again.',
    },
  });

  if (count > 0) logger.warn({ count }, 'reclaimed stalled analyses');
  return count;
}

/** Identity the cron sweep runs analyses under, when nobody is signed in. */
export const SYSTEM_ACTOR_ID = 'system:cron';
export const SYSTEM_ACTOR_EMAIL = 'cron@quarantine.internal';

/**
 * The context the scheduler runs a queued analysis under.
 *
 * `orgId` is taken from the analysis row itself, never from a request, so this
 * grants no cross-tenant reach: the sweep can only ever run an analysis inside
 * the org that already owns it. `OWNER` is the role because the scheduler is
 * not a member of anything and must not be blocked by one; it is used solely
 * for `assertCan`, and nothing on this path writes `userId` to a row.
 */
export function systemContext(orgId: string): AuthContext & { actorEmail: string } {
  return {
    userId: SYSTEM_ACTOR_ID,
    orgId,
    role: Role.OWNER,
    actorEmail: SYSTEM_ACTOR_EMAIL,
  };
}
