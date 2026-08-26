import { AnalysisStatus, CorpusLabel, Ecosystem, type Prisma, SignalFamily, Verdict } from '@prisma/client';
import { z } from 'zod';

import { audit } from '@/lib/audit';
import { VERDICT_META } from '@/lib/constants';
import { prisma } from '@/lib/db';
import { NotFoundError, ValidationError } from '@/lib/errors';
import { assertCan, type AuthContext } from '@/lib/rbac';
import { ENGINE_VERSION } from '@/lib/services/analysis.service';

/**
 * The labelled evaluation corpus, and the evaluation that runs against it.
 *
 * Two things about tenancy, because this file sits on the boundary.
 *
 * The corpus itself is global (like Package and Rule): a label saying
 * `event-stream@3.3.6 is malicious` is a fact about a published artefact, not
 * about anybody's organisation. Managing it needs `corpus:manage`, which only
 * admins hold.
 *
 * An EvalRun measures *the engine*. The corpus is global and the engine is
 * deterministic for a given tarball, so precision and recall do not depend on
 * who ran the evaluation. Only aggregate counts are persisted — no coordinates,
 * no analysis ids, nothing that says which tenant's analyses were read. The
 * analyses the numbers are computed from are the caller's own, filtered on
 * `ctx.orgId` like everything else.
 *
 * Nothing here downloads or executes anything: an evaluation reads verdicts
 * that already exist. Coordinates with no analysis are reported as uncovered
 * rather than silently counted as correct.
 */

export interface RequestInfo {
  ip?: string | null;
  userAgent?: string | null;
}

// ---------------------------------------------------------------------------
// Corpus management
// ---------------------------------------------------------------------------

export interface CorpusEntryRow {
  id: string;
  ecosystem: Ecosystem;
  packageName: string;
  version: string;
  label: CorpusLabel;
  source: string;
  notes: string | null;
  expectedSignals: string[];
  tarballSha256: string | null;
  createdAt: Date;
  /** The caller's own most recent verdict for this coordinate, if any. */
  observedVerdict: Verdict | null;
  observedAt: Date | null;
  analysisId: string | null;
}

export interface CorpusSummary {
  entries: CorpusEntryRow[];
  malicious: number;
  clean: number;
  covered: number;
  uncovered: number;
  withHash: number;
}

export async function listCorpus(ctx: AuthContext): Promise<CorpusSummary> {
  assertCan(ctx, 'corpus:read', { orgId: ctx.orgId });

  const entries = await prisma.corpusEntry.findMany({
    orderBy: [{ label: 'asc' }, { packageName: 'asc' }],
  });

  // One query for every coordinate the corpus names, scoped to this org.
  const analyses = await prisma.analysis.findMany({
    where: {
      orgId: ctx.orgId,
      verdict: { not: null },
      packageVersion: {
        OR: entries.map((entry) => ({
          version: entry.version,
          package: { ecosystem: entry.ecosystem, name: entry.packageName },
        })),
      },
    },
    select: {
      id: true,
      verdict: true,
      completedAt: true,
      packageVersion: {
        select: { version: true, package: { select: { ecosystem: true, name: true } } },
      },
    },
    orderBy: { completedAt: 'desc' },
  });

  const observed = new Map<string, (typeof analyses)[number]>();
  for (const analysis of analyses) {
    const key = `${analysis.packageVersion.package.ecosystem}:${analysis.packageVersion.package.name}@${analysis.packageVersion.version}`;
    if (!observed.has(key)) observed.set(key, analysis);
  }

  const rows: CorpusEntryRow[] = entries.map((entry) => {
    const match = observed.get(`${entry.ecosystem}:${entry.packageName}@${entry.version}`);
    return {
      id: entry.id,
      ecosystem: entry.ecosystem,
      packageName: entry.packageName,
      version: entry.version,
      label: entry.label,
      source: entry.source,
      notes: entry.notes,
      expectedSignals: entry.expectedSignals,
      tarballSha256: entry.tarballSha256,
      createdAt: entry.createdAt,
      observedVerdict: match?.verdict ?? null,
      observedAt: match?.completedAt ?? null,
      analysisId: match?.id ?? null,
    };
  });

  return {
    entries: rows,
    malicious: rows.filter((row) => row.label === CorpusLabel.MALICIOUS).length,
    clean: rows.filter((row) => row.label === CorpusLabel.CLEAN).length,
    covered: rows.filter((row) => row.observedVerdict !== null).length,
    uncovered: rows.filter((row) => row.observedVerdict === null).length,
    withHash: rows.filter((row) => row.tarballSha256 !== null).length,
  };
}

export const corpusEntrySchema = z.object({
  ecosystem: z.nativeEnum(Ecosystem).default(Ecosystem.NPM),
  packageName: z.string().trim().min(1).max(214),
  version: z.string().trim().min(1).max(64),
  label: z.nativeEnum(CorpusLabel),
  source: z.string().trim().min(2, 'Say where this label came from.').max(200),
  notes: z.string().trim().max(1000).optional(),
  expectedSignals: z.array(z.string().trim().max(20)).max(20).default([]),
  /**
   * SHA-256 of the exact tarball. The only route to a KNOWN_MALICIOUS verdict
   * by assertion, so it is validated as a digest and never as free text.
   */
  tarballSha256: z
    .string()
    .trim()
    .regex(/^[0-9a-f]{64}$/i, 'A SHA-256 digest is 64 hex characters.')
    .optional(),
});

export type CorpusEntryInput = z.infer<typeof corpusEntrySchema>;

export async function createCorpusEntry(
  ctx: AuthContext & { actorEmail: string },
  input: z.input<typeof corpusEntrySchema>,
  request: RequestInfo = {},
): Promise<{ id: string }> {
  assertCan(ctx, 'corpus:manage', { orgId: ctx.orgId });

  const parsed = corpusEntrySchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const clash = await prisma.corpusEntry.findFirst({
    where: {
      ecosystem: parsed.data.ecosystem,
      packageName: parsed.data.packageName,
      version: parsed.data.version,
    },
    select: { id: true },
  });
  if (clash) throw new ValidationError('That coordinate is already in the corpus.');

  const created = await prisma.corpusEntry.create({
    data: {
      ecosystem: parsed.data.ecosystem,
      packageName: parsed.data.packageName,
      version: parsed.data.version,
      label: parsed.data.label,
      source: parsed.data.source,
      notes: parsed.data.notes ?? null,
      expectedSignals: parsed.data.expectedSignals,
      tarballSha256: parsed.data.tarballSha256?.toLowerCase() ?? null,
    },
    select: { id: true },
  });

  await audit(
    ctx,
    'corpus.entry_created',
    { type: 'CorpusEntry', id: created.id },
    { packageName: parsed.data.packageName, label: parsed.data.label },
    request,
  );

  return created;
}

export async function deleteCorpusEntry(
  ctx: AuthContext & { actorEmail: string },
  entryId: string,
  request: RequestInfo = {},
): Promise<void> {
  assertCan(ctx, 'corpus:manage', { orgId: ctx.orgId });

  const existing = await prisma.corpusEntry.findUnique({
    where: { id: entryId },
    select: { id: true, packageName: true, version: true },
  });
  if (!existing) throw new NotFoundError('That corpus entry does not exist.');

  await prisma.corpusEntry.delete({ where: { id: existing.id } });

  await audit(
    ctx,
    'corpus.entry_deleted',
    { type: 'CorpusEntry', id: entryId },
    { packageName: existing.packageName, version: existing.version },
    request,
  );
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

export const POSITIVE_THRESHOLDS = [
  Verdict.SUSPICIOUS,
  Verdict.LIKELY_MALICIOUS,
  Verdict.KNOWN_MALICIOUS,
] as const;

export type PositiveThreshold = (typeof POSITIVE_THRESHOLDS)[number];

export interface FamilyMetric {
  family: SignalFamily;
  /** Corpus entries labelled malicious where this family fired. */
  truePositiveHits: number;
  /** Corpus entries labelled clean where this family fired — the noise measure. */
  falsePositiveHits: number;
  maliciousCoverage: number;
}

export interface RuleContribution {
  ruleId: string;
  family: SignalFamily;
  onMalicious: number;
  onClean: number;
  /** onMalicious / (onMalicious + onClean); 0 when the rule never fired. */
  precision: number;
}

export interface EvaluationCase {
  entryId: string;
  ecosystem: Ecosystem;
  packageName: string;
  version: string;
  label: CorpusLabel;
  verdict: Verdict | null;
  predictedPositive: boolean;
  outcome: 'TP' | 'FP' | 'TN' | 'FN' | 'UNCOVERED';
  durationMs: number | null;
  analysisId: string | null;
}

export interface EvaluationResult {
  threshold: PositiveThreshold;
  corpusSize: number;
  covered: number;
  uncovered: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1: number;
  falsePositiveRate: number;
  meanLatencyMs: number;
  p95LatencyMs: number;
  latencies: number[];
  families: FamilyMetric[];
  rules: RuleContribution[];
  cases: EvaluationCase[];
  engineVersion: string;
  ranAt: Date;
}

function isPositive(verdict: Verdict | null, threshold: PositiveThreshold): boolean {
  if (!verdict) return false;
  return VERDICT_META[verdict].rank <= VERDICT_META[threshold].rank;
}

function percentile(sorted: readonly number[], fraction: number): number {
  if (sorted.length === 0) return 0;
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(fraction * sorted.length) - 1));
  return sorted[index] ?? 0;
}

function ratio(numerator: number, denominator: number): number {
  return denominator === 0 ? 0 : numerator / denominator;
}

/**
 * Score the engine against the corpus using analyses that already exist.
 *
 * `persist` writes an EvalRun row, which is what the public research page
 * reads. It requires `eval:run`; the read-only computation only needs
 * `corpus:read`, so a viewer can look at the numbers without being able to
 * publish new ones.
 */
export async function runEvaluation(
  ctx: AuthContext & { actorEmail: string },
  options: { threshold?: PositiveThreshold; persist?: boolean } = {},
): Promise<EvaluationResult> {
  assertCan(ctx, 'corpus:read', { orgId: ctx.orgId });

  const threshold = options.threshold ?? Verdict.SUSPICIOUS;
  const persist = options.persist ?? false;
  if (persist) assertCan(ctx, 'eval:run', { orgId: ctx.orgId });

  const entries = await prisma.corpusEntry.findMany({ orderBy: { packageName: 'asc' } });

  if (entries.length === 0) {
    throw new ValidationError('The corpus is empty. Add labelled entries before evaluating.');
  }

  const analyses = await prisma.analysis.findMany({
    where: {
      orgId: ctx.orgId,
      status: { in: [AnalysisStatus.COMPLETED, AnalysisStatus.PARTIAL] },
      verdict: { not: null },
      packageVersion: {
        OR: entries.map((entry) => ({
          version: entry.version,
          package: { ecosystem: entry.ecosystem, name: entry.packageName },
        })),
      },
    },
    select: {
      id: true,
      verdict: true,
      durationMs: true,
      completedAt: true,
      packageVersion: {
        select: { version: true, package: { select: { ecosystem: true, name: true } } },
      },
      signalHits: { select: { ruleId: true, family: true } },
    },
    orderBy: { completedAt: 'desc' },
  });

  type AnalysisRow = (typeof analyses)[number];
  const latest = new Map<string, AnalysisRow>();
  for (const analysis of analyses) {
    const key = `${analysis.packageVersion.package.ecosystem}:${analysis.packageVersion.package.name}@${analysis.packageVersion.version}`;
    if (!latest.has(key)) latest.set(key, analysis);
  }

  const cases: EvaluationCase[] = [];
  const latencies: number[] = [];

  const familyStats = new Map<SignalFamily, { tp: number; fp: number }>();
  for (const family of Object.values(SignalFamily)) familyStats.set(family, { tp: 0, fp: 0 });

  const ruleStats = new Map<string, RuleContribution>();

  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;

  for (const entry of entries) {
    const analysis = latest.get(`${entry.ecosystem}:${entry.packageName}@${entry.version}`);

    if (!analysis) {
      cases.push({
        entryId: entry.id,
        ecosystem: entry.ecosystem,
        packageName: entry.packageName,
        version: entry.version,
        label: entry.label,
        verdict: null,
        predictedPositive: false,
        outcome: 'UNCOVERED',
        durationMs: null,
        analysisId: null,
      });
      continue;
    }

    const predicted = isPositive(analysis.verdict, threshold);
    const actual = entry.label === CorpusLabel.MALICIOUS;

    let outcome: EvaluationCase['outcome'];
    if (predicted && actual) {
      outcome = 'TP';
      tp += 1;
    } else if (predicted && !actual) {
      outcome = 'FP';
      fp += 1;
    } else if (!predicted && actual) {
      outcome = 'FN';
      fn += 1;
    } else {
      outcome = 'TN';
      tn += 1;
    }

    if (analysis.durationMs !== null) latencies.push(analysis.durationMs);

    const seenFamilies = new Set<SignalFamily>();
    const seenRules = new Set<string>();

    for (const hit of analysis.signalHits) {
      if (!seenFamilies.has(hit.family)) {
        seenFamilies.add(hit.family);
        const stat = familyStats.get(hit.family);
        if (stat) {
          if (actual) stat.tp += 1;
          else stat.fp += 1;
        }
      }

      if (!seenRules.has(hit.ruleId)) {
        seenRules.add(hit.ruleId);
        const rule = ruleStats.get(hit.ruleId) ?? {
          ruleId: hit.ruleId,
          family: hit.family,
          onMalicious: 0,
          onClean: 0,
          precision: 0,
        };
        if (actual) rule.onMalicious += 1;
        else rule.onClean += 1;
        ruleStats.set(hit.ruleId, rule);
      }
    }

    cases.push({
      entryId: entry.id,
      ecosystem: entry.ecosystem,
      packageName: entry.packageName,
      version: entry.version,
      label: entry.label,
      verdict: analysis.verdict,
      predictedPositive: predicted,
      outcome,
      durationMs: analysis.durationMs,
      analysisId: analysis.id,
    });
  }

  const maliciousCovered = cases.filter(
    (row) => row.label === CorpusLabel.MALICIOUS && row.outcome !== 'UNCOVERED',
  ).length;

  const families: FamilyMetric[] = [...familyStats.entries()].map(([family, stat]) => ({
    family,
    truePositiveHits: stat.tp,
    falsePositiveHits: stat.fp,
    maliciousCoverage: Math.round(ratio(stat.tp, maliciousCovered) * 1000) / 1000,
  }));

  const rules = [...ruleStats.values()]
    .map((rule) => ({
      ...rule,
      precision: Math.round(ratio(rule.onMalicious, rule.onMalicious + rule.onClean) * 1000) / 1000,
    }))
    .sort((a, b) => b.onClean - a.onClean || b.onMalicious - a.onMalicious);

  const sortedLatencies = [...latencies].sort((a, b) => a - b);
  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);

  const result: EvaluationResult = {
    threshold,
    corpusSize: entries.length,
    covered: cases.filter((row) => row.outcome !== 'UNCOVERED').length,
    uncovered: cases.filter((row) => row.outcome === 'UNCOVERED').length,
    truePositives: tp,
    falsePositives: fp,
    trueNegatives: tn,
    falseNegatives: fn,
    precision: Math.round(precision * 1000) / 1000,
    recall: Math.round(recall * 1000) / 1000,
    f1: Math.round(ratio(2 * precision * recall, precision + recall) * 1000) / 1000,
    falsePositiveRate: Math.round(ratio(fp, fp + tn) * 1000) / 1000,
    meanLatencyMs:
      latencies.length === 0
        ? 0
        : Math.round(latencies.reduce((total, value) => total + value, 0) / latencies.length),
    p95LatencyMs: percentile(sortedLatencies, 0.95),
    latencies: sortedLatencies,
    families,
    rules,
    cases,
    engineVersion: ENGINE_VERSION,
    ranAt: new Date(),
  };

  if (persist) {
    await prisma.evalRun.create({
      data: {
        corpusSize: result.corpusSize,
        truePositives: tp,
        falsePositives: fp,
        trueNegatives: tn,
        falseNegatives: fn,
        precision: result.precision,
        recall: result.recall,
        f1: result.f1,
        falsePositiveRate: result.falsePositiveRate,
        meanLatencyMs: result.meanLatencyMs,
        p95LatencyMs: result.p95LatencyMs,
        engineVersion: ENGINE_VERSION,
        perFamilyMetrics: {
          threshold,
          covered: result.covered,
          uncovered: result.uncovered,
          families: families as unknown as Prisma.InputJsonValue,
        } as unknown as Prisma.InputJsonValue,
      },
    });

    await audit(
      ctx,
      'eval.ran',
      { type: 'EvalRun', id: null },
      { corpusSize: result.corpusSize, precision: result.precision, recall: result.recall },
      {},
    );
  }

  return result;
}

/** Previous runs, newest first, for the trend on the evaluation page. */
export async function listEvalRuns(ctx: AuthContext, take = 20) {
  assertCan(ctx, 'corpus:read', { orgId: ctx.orgId });

  return prisma.evalRun.findMany({
    orderBy: { ranAt: 'desc' },
    take: Math.min(Math.max(take, 1), 50),
  });
}
