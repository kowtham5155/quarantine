import { SignalFamily } from '@prisma/client';

import { prisma } from '@/lib/db';
import type { RuleMeta } from '@/lib/services/package.service';

/**
 * The public reference data: the rule catalogue and the evaluation corpus.
 *
 * These are the two things in the system that are deliberately *not* tenant
 * scoped, and so the two places where the rule "every service function takes a
 * ctx" does not apply. Nothing here reads an Analysis, a SignalHit or anything
 * else an organisation owns — a rule's definition, weight and remediation are
 * the same for everyone, and publishing them is the point: a detection you
 * cannot inspect is a detection you will eventually ignore.
 *
 * Anything that joins a rule to an org's findings lives in package.service.ts
 * and takes a ctx like everything else.
 */

export interface RuleCatalogueEntry extends RuleMeta {
  /** Number of corpus entries whose expected signals name this rule. */
  corpusCoverage: number;
}

export interface RuleCatalogue {
  rules: RuleCatalogueEntry[];
  byFamily: Array<{ family: SignalFamily; count: number; enabled: number }>;
  total: number;
  enabled: number;
}

export async function getRuleCatalogue(): Promise<RuleCatalogue> {
  const [rules, corpus] = await Promise.all([
    prisma.rule.findMany({ orderBy: [{ family: 'asc' }, { ruleId: 'asc' }] }),
    prisma.corpusEntry.findMany({ select: { expectedSignals: true } }),
  ]);

  const coverage = new Map<string, number>();
  for (const entry of corpus) {
    for (const ruleId of entry.expectedSignals) {
      coverage.set(ruleId, (coverage.get(ruleId) ?? 0) + 1);
    }
  }

  const entries: RuleCatalogueEntry[] = rules.map((rule) => ({
    ruleId: rule.ruleId,
    family: rule.family,
    name: rule.name,
    description: rule.description,
    severity: rule.severity,
    baseWeight: rule.baseWeight,
    remediation: rule.remediation,
    references: rule.references,
    enabled: rule.enabled,
    falsePositiveNotes: rule.falsePositiveNotes,
    corpusCoverage: coverage.get(rule.ruleId) ?? 0,
  }));

  return {
    rules: entries,
    byFamily: Object.values(SignalFamily).map((family) => ({
      family,
      count: entries.filter((rule) => rule.family === family).length,
      enabled: entries.filter((rule) => rule.family === family && rule.enabled).length,
    })),
    total: entries.length,
    enabled: entries.filter((rule) => rule.enabled).length,
  };
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

export interface FamilyMetric {
  family: SignalFamily;
  precision: number | null;
  recall: number | null;
  f1: number | null;
}

export interface EvaluationRun {
  id: string;
  ranAt: Date;
  engineVersion: string;
  corpusSize: number;
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
  perFamily: FamilyMetric[];
  notes: string | null;
}

export interface CorpusComposition {
  total: number;
  malicious: number;
  clean: number;
  byEcosystem: Array<{ ecosystem: string; malicious: number; clean: number }>;
  /** Distinct provenance strings, so the page can name where the labels came from. */
  sources: Array<{ source: string; count: number }>;
}

export interface EvaluationSummary {
  latest: EvaluationRun | null;
  history: EvaluationRun[];
  corpus: CorpusComposition;
}

function numberOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function toPerFamily(raw: unknown): { metrics: FamilyMetric[]; notes: string | null } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { metrics: [], notes: null };

  const record = raw as Record<string, unknown>;
  const notes = typeof record.notes === 'string' ? record.notes : null;
  const byFamily =
    record.byFamily && typeof record.byFamily === 'object' && !Array.isArray(record.byFamily)
      ? (record.byFamily as Record<string, unknown>)
      : {};

  const metrics: FamilyMetric[] = [];
  for (const family of Object.values(SignalFamily)) {
    const entry = byFamily[family];
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const values = entry as Record<string, unknown>;
    metrics.push({
      family,
      precision: numberOrNull(values.precision),
      recall: numberOrNull(values.recall),
      f1: numberOrNull(values.f1),
    });
  }

  return { metrics, notes };
}

export async function getEvaluationSummary(): Promise<EvaluationSummary> {
  const [runs, byLabel, sources] = await Promise.all([
    prisma.evalRun.findMany({ orderBy: { ranAt: 'desc' }, take: 10 }),
    prisma.corpusEntry.groupBy({ by: ['label', 'ecosystem'], _count: { _all: true } }),
    prisma.corpusEntry.groupBy({ by: ['source'], _count: { _all: true } }),
  ]);

  const history: EvaluationRun[] = runs.map((run) => {
    const { metrics, notes } = toPerFamily(run.perFamilyMetrics);
    return {
      id: run.id,
      ranAt: run.ranAt,
      engineVersion: run.engineVersion,
      corpusSize: run.corpusSize,
      truePositives: run.truePositives,
      falsePositives: run.falsePositives,
      trueNegatives: run.trueNegatives,
      falseNegatives: run.falseNegatives,
      precision: run.precision,
      recall: run.recall,
      f1: run.f1,
      falsePositiveRate: run.falsePositiveRate,
      meanLatencyMs: run.meanLatencyMs,
      p95LatencyMs: run.p95LatencyMs,
      perFamily: metrics,
      notes,
    };
  });

  const ecosystems = [...new Set(byLabel.map((row) => row.ecosystem))];

  return {
    latest: history[0] ?? null,
    history,
    corpus: {
      total: byLabel.reduce((total, row) => total + row._count._all, 0),
      malicious: byLabel
        .filter((row) => row.label === 'MALICIOUS')
        .reduce((total, row) => total + row._count._all, 0),
      clean: byLabel
        .filter((row) => row.label === 'CLEAN')
        .reduce((total, row) => total + row._count._all, 0),
      byEcosystem: ecosystems.map((ecosystem) => ({
        ecosystem,
        malicious:
          byLabel.find((row) => row.ecosystem === ecosystem && row.label === 'MALICIOUS')?._count
            ._all ?? 0,
        clean:
          byLabel.find((row) => row.ecosystem === ecosystem && row.label === 'CLEAN')?._count
            ._all ?? 0,
      })),
      sources: sources
        .map((row) => ({ source: row.source, count: row._count._all }))
        .sort((a, b) => b.count - a.count),
    },
  };
}
