import { type Ecosystem, Severity, type SignalFamily, Verdict } from '@prisma/client';
import { z } from 'zod';

import { audit } from '@/lib/audit';
import { prisma } from '@/lib/db';
import { NotFoundError, ValidationError } from '@/lib/errors';
import { assertCan, type AuthContext } from '@/lib/rbac';

/**
 * The rule catalogue, and the parts of it an administrator may tune.
 *
 * The rules themselves are global — a rule is a statement about how the engine
 * reads code, not about a tenant — so the catalogue is read without an org
 * filter. Everything derived from *firings* is tenant data and is filtered on
 * `ctx.orgId`: how often a rule fires, and on what, is a description of the
 * caller's own dependency estate.
 *
 * Changing a weight or disabling a rule affects analyses run from that point
 * on. Stored verdicts are not recomputed, because a verdict is a record of what
 * the engine concluded at a moment in time and silently rewriting history would
 * make every report unciteable. Re-run a scan to see a new weight applied.
 */

export interface RequestInfo {
  ip?: string | null;
  userAgent?: string | null;
}

export interface RuleRow {
  id: string;
  ruleId: string;
  family: SignalFamily;
  name: string;
  description: string;
  severity: Severity;
  baseWeight: number;
  remediation: string;
  references: string[];
  enabled: boolean;
  falsePositiveNotes: string | null;
  /** Analyses in this org where the rule fired at least once. */
  firedOnAnalyses: number;
  /** Distinct package versions in this org where it fired. */
  firedOnVersions: number;
  /** Firings that landed on an analysis whose verdict was CLEAN or LOW_RISK. */
  firedOnBenign: number;
  updatedAt: Date;
}

/** Verdicts that mean "the analysis did not conclude anything was wrong". */
const BENIGN_VERDICTS: Verdict[] = [Verdict.CLEAN, Verdict.LOW_RISK];

export async function listRules(ctx: AuthContext): Promise<RuleRow[]> {
  assertCan(ctx, 'rule:read', { orgId: ctx.orgId });

  const rules = await prisma.rule.findMany({ orderBy: { ruleId: 'asc' } });

  // One pass over this org's hits; the catalogue is small enough that the
  // alternative (a groupBy per rule) is more round trips for no benefit.
  const hits = await prisma.signalHit.findMany({
    where: { analysis: { orgId: ctx.orgId } },
    select: {
      ruleId: true,
      analysisId: true,
      analysis: { select: { packageVersionId: true, verdict: true } },
    },
  });

  const stats = new Map<
    string,
    { analyses: Set<string>; versions: Set<string>; benign: Set<string> }
  >();

  for (const hit of hits) {
    const stat = stats.get(hit.ruleId) ?? {
      analyses: new Set<string>(),
      versions: new Set<string>(),
      benign: new Set<string>(),
    };
    stat.analyses.add(hit.analysisId);
    stat.versions.add(hit.analysis.packageVersionId);
    if (hit.analysis.verdict && BENIGN_VERDICTS.includes(hit.analysis.verdict)) {
      stat.benign.add(hit.analysisId);
    }
    stats.set(hit.ruleId, stat);
  }

  return rules.map((rule) => {
    const stat = stats.get(rule.ruleId);
    return {
      id: rule.id,
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
      firedOnAnalyses: stat?.analyses.size ?? 0,
      firedOnVersions: stat?.versions.size ?? 0,
      firedOnBenign: stat?.benign.size ?? 0,
      updatedAt: rule.updatedAt,
    };
  });
}

export interface RuleFiring {
  analysisId: string;
  packageVersionId: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  verdict: Verdict | null;
  completedAt: Date | null;
  /** Hits this rule produced inside that one analysis. */
  hitCount: number;
  /** HOSTILE INPUT: verbatim from the analysed package. Escape on render. */
  sampleExcerpt: string | null;
  sampleFilePath: string | null;
}

export interface RuleDetail {
  rule: RuleRow;
  firings: RuleFiring[];
  /** Firings beyond the page returned. */
  truncated: boolean;
}

export async function getRule(
  ctx: AuthContext,
  ruleId: string,
  take = 100,
): Promise<RuleDetail> {
  assertCan(ctx, 'rule:read', { orgId: ctx.orgId });

  const rules = await listRules(ctx);
  const rule = rules.find((candidate) => candidate.ruleId === ruleId);
  if (!rule) throw new NotFoundError('That rule is not in the catalogue.');

  const hits = await prisma.signalHit.findMany({
    where: { ruleId, analysis: { orgId: ctx.orgId } },
    select: {
      analysisId: true,
      filePath: true,
      excerpt: true,
      analysis: {
        select: {
          id: true,
          verdict: true,
          completedAt: true,
          packageVersionId: true,
          packageVersion: {
            select: { version: true, package: { select: { ecosystem: true, name: true } } },
          },
        },
      },
    },
    orderBy: { createdAt: 'desc' },
    take: 1000,
  });

  const byAnalysis = new Map<string, RuleFiring>();

  for (const hit of hits) {
    const existing = byAnalysis.get(hit.analysisId);
    if (existing) {
      existing.hitCount += 1;
      continue;
    }

    byAnalysis.set(hit.analysisId, {
      analysisId: hit.analysisId,
      packageVersionId: hit.analysis.packageVersionId,
      ecosystem: hit.analysis.packageVersion.package.ecosystem,
      name: hit.analysis.packageVersion.package.name,
      version: hit.analysis.packageVersion.version,
      verdict: hit.analysis.verdict,
      completedAt: hit.analysis.completedAt,
      hitCount: 1,
      sampleExcerpt: hit.excerpt,
      sampleFilePath: hit.filePath,
    });
  }

  const firings = [...byAnalysis.values()].sort(
    (a, b) => (b.completedAt?.getTime() ?? 0) - (a.completedAt?.getTime() ?? 0),
  );

  return {
    rule,
    firings: firings.slice(0, take),
    truncated: firings.length > take,
  };
}

export const updateRuleSchema = z.object({
  /**
   * Weight is bounded to the range the verdict thresholds are calibrated
   * against. A rule at weight 400 would not be "tuned", it would be a hard
   * trigger with no review step.
   */
  baseWeight: z.number().min(0).max(50),
  severity: z.nativeEnum(Severity),
  enabled: z.boolean(),
  falsePositiveNotes: z.string().trim().max(2000).optional(),
});

export type UpdateRuleInput = z.infer<typeof updateRuleSchema>;

export async function updateRule(
  ctx: AuthContext & { actorEmail: string },
  ruleId: string,
  input: UpdateRuleInput,
  request: RequestInfo = {},
): Promise<void> {
  assertCan(ctx, 'rule:update', { orgId: ctx.orgId });

  const parsed = updateRuleSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const existing = await prisma.rule.findUnique({ where: { ruleId }, select: { id: true, baseWeight: true, enabled: true } });
  if (!existing) throw new NotFoundError('That rule is not in the catalogue.');

  await prisma.rule.update({
    where: { id: existing.id },
    data: {
      baseWeight: parsed.data.baseWeight,
      severity: parsed.data.severity,
      enabled: parsed.data.enabled,
      falsePositiveNotes: parsed.data.falsePositiveNotes ?? null,
    },
  });

  await audit(
    ctx,
    'rule.updated',
    { type: 'Rule', id: ruleId },
    {
      from: { baseWeight: existing.baseWeight, enabled: existing.enabled },
      to: { baseWeight: parsed.data.baseWeight, enabled: parsed.data.enabled },
    },
    request,
  );
}
