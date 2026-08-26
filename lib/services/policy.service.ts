import {
  AlertType,
  type Ecosystem,
  ExceptionState,
  PolicyAction,
  type Prisma,
  QuarantineState,
  Severity,
  SignalFamily,
  type Verdict,
  ViolationState,
} from '@prisma/client';
import { z } from 'zod';

import { audit } from '@/lib/audit';
import { VERDICT_META } from '@/lib/constants';
import {
  CONDITION_LABELS,
  CONDITION_TYPES,
  describeCondition,
  policyConditionSchema,
  type PolicyCondition,
  type PolicyConditionType,
} from '@/lib/policy-conditions';
import { prisma } from '@/lib/db';
import { logger } from '@/lib/logger';
import { NotFoundError, ValidationError } from '@/lib/errors';
import { assertCan, type AuthContext } from '@/lib/rbac';

/**
 * Policy: the org's own rules about what it will accept, evaluated against
 * analyses the engine has already produced.
 *
 * Two deliberate design decisions live here.
 *
 * 1. A policy is a conjunction. Every condition on it must hold. "Any of" is
 *    expressed by writing two policies, which keeps the evaluation trace
 *    readable — a violation names exactly one policy and every condition on it
 *    was true.
 * 2. Evaluation is first-match-wins in ascending `priority`. Firewall
 *    semantics: an ALLOW at priority 10 shadows a BLOCK at priority 20, which
 *    is how an exemption for a vendored internal package is expressed without
 *    a special case in the engine. The list page renders policies in that
 *    order for exactly this reason.
 *
 * Every query is filtered on `ctx.orgId` (CLAUDE.md rule 4) — policy is the
 * control an org is audited against, so leaking one across tenants would be a
 * disclosure of that org's security posture.
 */

export interface RequestInfo {
  ip?: string | null;
  userAgent?: string | null;
}

// ---------------------------------------------------------------------------
// Conditions
// ---------------------------------------------------------------------------

/**
 * The condition vocabulary lives in `lib/policy-conditions.ts` so that the
 * builder and the policy list — both client components — can reach it without
 * importing this module and dragging Prisma into the browser bundle. It is
 * re-exported here because a condition only means anything alongside the
 * evaluation code below.
 */
export {
  CONDITION_LABELS,
  CONDITION_TYPES,
  describeCondition,
  policyConditionSchema,
  type PolicyCondition,
  type PolicyConditionType,
};

/**
 * Read the `conditions` JSON column back into typed conditions.
 *
 * A row written by an older build, or hand-edited in the database, must not
 * take down the page that renders it: anything that fails to parse is dropped
 * and counted rather than thrown. A policy whose conditions all dropped matches
 * nothing (see `matchesPolicy`), which is the safe direction to fail in for
 * BLOCK and the honest one for ALLOW.
 */
export function parseConditions(value: Prisma.JsonValue): {
  conditions: PolicyCondition[];
  dropped: number;
} {
  const raw = Array.isArray(value) ? value : [];
  const conditions: PolicyCondition[] = [];
  let dropped = 0;

  for (const entry of raw) {
    const parsed = policyConditionSchema.safeParse(entry);
    if (parsed.success) conditions.push(parsed.data);
    else dropped += 1;
  }

  return { conditions, dropped };
}

// ---------------------------------------------------------------------------
// Subjects
// ---------------------------------------------------------------------------

/**
 * Everything a condition can be evaluated against, flattened out of one
 * analysis. Building this explicitly (rather than passing a Prisma row around)
 * is what lets the preview run a proposed policy over historical analyses with
 * the same code path production uses.
 */
export interface PolicySubject {
  analysisId: string;
  packageVersionId: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  verdict: Verdict | null;
  weightedScore: number | null;
  confidence: number | null;
  completedAt: Date | null;
  firedRuleIds: string[];
  familyScores: Record<SignalFamily, number>;
  /** Age of the *package*, not the version: a new version of a 9-year-old library is not a new package. */
  firstPublishedAt: Date | null;
  maintainerCount: number;
  license: string | null;
}

const SUBJECT_INCLUDE = {
  packageVersion: { include: { package: true } },
  signalHits: {
    select: {
      ruleId: true,
      family: true,
      weight: true,
      confidence: true,
      contextModifier: true,
    },
  },
} satisfies Prisma.AnalysisInclude;

type SubjectRow = Prisma.AnalysisGetPayload<{ include: typeof SUBJECT_INCLUDE }>;

function emptyFamilyScores(): Record<SignalFamily, number> {
  return {
    [SignalFamily.INSTALL]: 0,
    [SignalFamily.OBFUSCATION]: 0,
    [SignalFamily.CAPABILITY]: 0,
    [SignalFamily.TYPOSQUAT]: 0,
    [SignalFamily.MAINTAINER]: 0,
    [SignalFamily.PROVENANCE]: 0,
  };
}

export function toSubject(row: SubjectRow): PolicySubject {
  const familyScores = emptyFamilyScores();
  const seen = new Set<string>();

  // A rule that matched forty lines contributes its weight once, matching the
  // report's own breakdown. Counting per hit would let one noisy regex clear
  // any family threshold on its own.
  for (const hit of row.signalHits) {
    if (seen.has(hit.ruleId)) continue;
    seen.add(hit.ruleId);
    familyScores[hit.family] += hit.weight * hit.confidence * hit.contextModifier;
  }

  for (const family of Object.values(SignalFamily)) {
    familyScores[family] = Math.round(familyScores[family] * 100) / 100;
  }

  return {
    analysisId: row.id,
    packageVersionId: row.packageVersionId,
    ecosystem: row.packageVersion.package.ecosystem,
    name: row.packageVersion.package.name,
    version: row.packageVersion.version,
    verdict: row.verdict,
    weightedScore: row.weightedScore,
    confidence: row.confidence,
    completedAt: row.completedAt,
    firedRuleIds: [...seen],
    familyScores,
    firstPublishedAt:
      row.packageVersion.package.firstPublishedAt ?? row.packageVersion.publishedAt ?? null,
    maintainerCount: row.packageVersion.package.maintainerCount,
    license: row.packageVersion.package.license,
  };
}

const DAY_MS = 86_400_000;

function normaliseLicense(value: string): string {
  return value.trim().toLowerCase();
}

/** Does one condition hold for this subject? */
export function matchesCondition(condition: PolicyCondition, subject: PolicySubject): boolean {
  switch (condition.type) {
    case 'verdict_at_least': {
      if (!subject.verdict) return false;
      // Lower rank is worse in VERDICT_META, so "at least this bad" is <=.
      return VERDICT_META[subject.verdict].rank <= VERDICT_META[condition.verdict].rank;
    }
    case 'rule_fired':
      return subject.firedRuleIds.includes(condition.ruleId);
    case 'family_score_at_least':
      return subject.familyScores[condition.family] >= condition.score;
    case 'package_age_below_days': {
      // Unknown age is not young. Treating "we do not know" as a match would
      // block every package whose registry withheld a publish time.
      if (!subject.firstPublishedAt) return false;
      return Date.now() - subject.firstPublishedAt.getTime() < condition.days * DAY_MS;
    }
    case 'maintainer_count_below':
      return subject.maintainerCount > 0 && subject.maintainerCount < condition.count;
    case 'license_not_in': {
      // An undeclared licence is not on the allowed list, and that is the point
      // of the condition — an unlicensed dependency is the thing being caught.
      const allowed = new Set(condition.licenses.map(normaliseLicense));
      if (!subject.license) return true;
      return !allowed.has(normaliseLicense(subject.license));
    }
    case 'ecosystem_is':
      return subject.ecosystem === condition.ecosystem;
  }
}

export interface EvaluablePolicy {
  id: string;
  name: string;
  action: PolicyAction;
  priority: number;
  enabled: boolean;
  conditions: PolicyCondition[];
}

/** A policy matches when every one of its conditions does. No conditions never matches. */
export function matchesPolicy(policy: EvaluablePolicy, subject: PolicySubject): boolean {
  if (policy.conditions.length === 0) return false;
  return policy.conditions.every((condition) => matchesCondition(condition, subject));
}

export interface PolicyDecision {
  action: PolicyAction;
  /** The policy that decided, or null when nothing matched. */
  policy: EvaluablePolicy | null;
  /** Every policy that would have matched, in evaluation order. */
  matched: EvaluablePolicy[];
}

/** First match wins, ascending priority, ties broken by name for determinism. */
export function evaluate(
  policies: readonly EvaluablePolicy[],
  subject: PolicySubject,
): PolicyDecision {
  const ordered = [...policies]
    .filter((policy) => policy.enabled)
    .sort((a, b) => a.priority - b.priority || a.name.localeCompare(b.name));

  const matched = ordered.filter((policy) => matchesPolicy(policy, subject));
  const decider = matched[0] ?? null;

  return {
    action: decider?.action ?? PolicyAction.ALLOW,
    policy: decider,
    matched,
  };
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

export const policyInputSchema = z.object({
  name: z.string().trim().min(2, 'Give the policy a name.').max(80),
  description: z.string().trim().max(500).optional(),
  action: z.nativeEnum(PolicyAction),
  priority: z.number().int().min(1).max(1000).default(100),
  enabled: z.boolean().default(true),
  conditions: z
    .array(policyConditionSchema)
    .min(1, 'A policy needs at least one condition.')
    .max(10, 'Ten conditions is the limit; split it into two policies.'),
});

export type PolicyInput = z.infer<typeof policyInputSchema>;

export interface PolicySummary {
  id: string;
  name: string;
  description: string | null;
  action: PolicyAction;
  priority: number;
  enabled: boolean;
  conditions: PolicyCondition[];
  /** Conditions in the row that no longer parse. Surfaced, never silently hidden. */
  droppedConditions: number;
  openViolations: number;
  totalViolations: number;
  createdAt: Date;
  updatedAt: Date;
}

type PolicyRow = Prisma.PolicyGetPayload<{ include: { violations: { select: { state: true } } } }>;

function toSummary(row: PolicyRow): PolicySummary {
  const { conditions, dropped } = parseConditions(row.conditions);

  return {
    id: row.id,
    name: row.name,
    description: row.description,
    action: row.action,
    priority: row.priority,
    enabled: row.enabled,
    conditions,
    droppedConditions: dropped,
    openViolations: row.violations.filter((violation) => violation.state === ViolationState.OPEN)
      .length,
    totalViolations: row.violations.length,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export async function listPolicies(ctx: AuthContext): Promise<PolicySummary[]> {
  assertCan(ctx, 'policy:read', { orgId: ctx.orgId });

  const rows = await prisma.policy.findMany({
    where: { orgId: ctx.orgId },
    include: { violations: { select: { state: true } } },
    orderBy: [{ priority: 'asc' }, { name: 'asc' }],
  });

  return rows.map(toSummary);
}

export async function getPolicy(ctx: AuthContext, policyId: string): Promise<PolicySummary> {
  assertCan(ctx, 'policy:read', { orgId: ctx.orgId });

  const row = await prisma.policy.findFirst({
    where: { id: policyId, orgId: ctx.orgId },
    include: { violations: { select: { state: true } } },
  });

  if (!row) throw new NotFoundError('Policy not found.');
  return toSummary(row);
}

/** Enabled policies in evaluation order, for the engine and the previews. */
export async function loadEvaluablePolicies(ctx: AuthContext): Promise<EvaluablePolicy[]> {
  const rows = await prisma.policy.findMany({
    where: { orgId: ctx.orgId, enabled: true },
    orderBy: [{ priority: 'asc' }, { name: 'asc' }],
  });

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    action: row.action,
    priority: row.priority,
    enabled: row.enabled,
    conditions: parseConditions(row.conditions).conditions,
  }));
}

async function assertNameFree(orgId: string, name: string, exceptId?: string): Promise<void> {
  const clash = await prisma.policy.findFirst({
    where: { orgId, name, ...(exceptId ? { NOT: { id: exceptId } } : {}) },
    select: { id: true },
  });

  if (clash) {
    throw new ValidationError('A policy with that name already exists.', {
      details: { fieldErrors: { name: ['A policy with that name already exists.'] } },
    });
  }
}

export async function createPolicy(
  ctx: AuthContext & { actorEmail: string },
  input: PolicyInput,
  request: RequestInfo = {},
): Promise<PolicySummary> {
  assertCan(ctx, 'policy:create', { orgId: ctx.orgId });

  const parsed = policyInputSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  await assertNameFree(ctx.orgId, parsed.data.name);

  const row = await prisma.policy.create({
    data: {
      orgId: ctx.orgId,
      name: parsed.data.name,
      description: parsed.data.description ?? null,
      action: parsed.data.action,
      priority: parsed.data.priority,
      enabled: parsed.data.enabled,
      conditions: parsed.data.conditions as unknown as Prisma.InputJsonValue,
    },
    include: { violations: { select: { state: true } } },
  });

  await audit(
    ctx,
    'policy.created',
    { type: 'Policy', id: row.id },
    { name: row.name, action: row.action, conditions: parsed.data.conditions.length },
    request,
  );

  return toSummary(row);
}

export async function updatePolicy(
  ctx: AuthContext & { actorEmail: string },
  policyId: string,
  input: PolicyInput,
  request: RequestInfo = {},
): Promise<PolicySummary> {
  assertCan(ctx, 'policy:update', { orgId: ctx.orgId });

  const parsed = policyInputSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const existing = await prisma.policy.findFirst({
    where: { id: policyId, orgId: ctx.orgId },
    select: { id: true, enabled: true },
  });
  if (!existing) throw new NotFoundError('Policy not found.');

  await assertNameFree(ctx.orgId, parsed.data.name, policyId);

  // Scoped by orgId as well as id: an id from another tenant updates nothing.
  const row = await prisma.policy.update({
    where: { id: existing.id },
    data: {
      name: parsed.data.name,
      description: parsed.data.description ?? null,
      action: parsed.data.action,
      priority: parsed.data.priority,
      enabled: parsed.data.enabled,
      conditions: parsed.data.conditions as unknown as Prisma.InputJsonValue,
    },
    include: { violations: { select: { state: true } } },
  });

  await audit(
    ctx,
    'policy.updated',
    { type: 'Policy', id: row.id },
    { name: row.name, action: row.action },
    request,
  );

  return toSummary(row);
}

export async function setPolicyEnabled(
  ctx: AuthContext & { actorEmail: string },
  policyId: string,
  enabled: boolean,
  request: RequestInfo = {},
): Promise<void> {
  assertCan(ctx, 'policy:update', { orgId: ctx.orgId });

  const result = await prisma.policy.updateMany({
    where: { id: policyId, orgId: ctx.orgId },
    data: { enabled },
  });

  if (result.count === 0) throw new NotFoundError('Policy not found.');

  await audit(
    ctx,
    enabled ? 'policy.enabled' : 'policy.disabled',
    { type: 'Policy', id: policyId },
    {},
    request,
  );
}

export async function deletePolicy(
  ctx: AuthContext & { actorEmail: string },
  policyId: string,
  request: RequestInfo = {},
): Promise<void> {
  assertCan(ctx, 'policy:delete', { orgId: ctx.orgId });

  const result = await prisma.policy.deleteMany({ where: { id: policyId, orgId: ctx.orgId } });
  if (result.count === 0) throw new NotFoundError('Policy not found.');

  await audit(ctx, 'policy.deleted', { type: 'Policy', id: policyId }, {}, request);
}

// ---------------------------------------------------------------------------
// Preview: "what would this have blocked"
// ---------------------------------------------------------------------------

export interface PreviewMatch {
  analysisId: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  verdict: Verdict | null;
  completedAt: Date | null;
  /** Which conditions carried the match, in the order they were written. */
  reasons: string[];
}

export interface PolicyPreview {
  /** Analyses considered — the org's completed analyses, newest first, capped. */
  evaluated: number;
  matched: number;
  action: PolicyAction;
  samples: PreviewMatch[];
  /** True when the org has more completed analyses than the preview window. */
  truncated: boolean;
  windowSize: number;
}

export const PREVIEW_WINDOW = 500;
const PREVIEW_SAMPLES = 25;

/**
 * Run a proposed condition set over analyses the org has already completed.
 *
 * This is a read: it writes no violations and changes no state. It is bounded
 * to the most recent `PREVIEW_WINDOW` analyses because a policy editor that
 * scans an unbounded table on every keystroke is a denial of service against
 * the org's own database.
 */
export async function previewPolicy(
  ctx: AuthContext,
  input: { conditions: PolicyCondition[]; action: PolicyAction },
): Promise<PolicyPreview> {
  assertCan(ctx, 'policy:read', { orgId: ctx.orgId });

  const parsed = z
    .object({
      conditions: z.array(policyConditionSchema).max(10),
      action: z.nativeEnum(PolicyAction),
    })
    .safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const [rows, total] = await Promise.all([
    prisma.analysis.findMany({
      where: { orgId: ctx.orgId, verdict: { not: null } },
      include: SUBJECT_INCLUDE,
      orderBy: { completedAt: 'desc' },
      take: PREVIEW_WINDOW,
    }),
    prisma.analysis.count({ where: { orgId: ctx.orgId, verdict: { not: null } } }),
  ]);

  const candidate: EvaluablePolicy = {
    id: 'preview',
    name: 'Preview',
    action: parsed.data.action,
    priority: 0,
    enabled: true,
    conditions: parsed.data.conditions,
  };

  const samples: PreviewMatch[] = [];
  let matched = 0;

  for (const row of rows) {
    const subject = toSubject(row);
    if (!matchesPolicy(candidate, subject)) continue;

    matched += 1;
    if (samples.length < PREVIEW_SAMPLES) {
      samples.push({
        analysisId: subject.analysisId,
        ecosystem: subject.ecosystem,
        name: subject.name,
        version: subject.version,
        verdict: subject.verdict,
        completedAt: subject.completedAt,
        reasons: candidate.conditions.map(describeCondition),
      });
    }
  }

  return {
    evaluated: rows.length,
    matched,
    action: parsed.data.action,
    samples,
    truncated: total > rows.length,
    windowSize: PREVIEW_WINDOW,
  };
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

export interface EnforcementOutcome {
  action: PolicyAction;
  policyId: string | null;
  policyName: string | null;
  violationId: string | null;
  quarantined: boolean;
  /** True when an approved, unexpired exception downgraded a BLOCK. */
  excepted: boolean;
}

/**
 * Is there a live exception covering this package version?
 *
 * Expiry is evaluated here rather than trusted from `state`, so an exception
 * whose expiry passed between the nightly sweep and this call is already
 * inert. `sweepExpiredExceptions` only tidies the stored state up afterwards.
 */
async function hasLiveException(
  orgId: string,
  packageVersionId: string,
  policyId: string | null,
): Promise<boolean> {
  const now = new Date();

  const found = await prisma.exception.findFirst({
    where: {
      orgId,
      packageVersionId,
      state: ExceptionState.APPROVED,
      AND: [
        { OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] },
        // An exception scoped to one policy does not excuse a different one;
        // one with no policy is org-wide for that package version.
        { OR: [{ policyId: null }, ...(policyId ? [{ policyId }] : [])] },
      ],
    },
    select: { id: true },
  });

  return found !== null;
}

/**
 * Evaluate this org's policies against one completed analysis and record what
 * follows: a violation for WARN and BLOCK, a quarantine hold and an alert for
 * BLOCK.
 *
 * Called after every analysis completes. Best-effort by contract — the caller
 * logs and swallows, because a policy that fails to evaluate must not lose the
 * evidence the engine just produced.
 */
export async function applyPolicies(
  ctx: AuthContext & { actorEmail: string },
  analysisId: string,
  projectId: string | null = null,
): Promise<EnforcementOutcome> {
  const row = await prisma.analysis.findFirst({
    where: { id: analysisId, orgId: ctx.orgId },
    include: SUBJECT_INCLUDE,
  });

  if (!row) throw new NotFoundError('Analysis not found.');

  const subject = toSubject(row);
  const policies = await loadEvaluablePolicies(ctx);
  const decision = evaluate(policies, subject);

  const idle: EnforcementOutcome = {
    action: decision.action,
    policyId: decision.policy?.id ?? null,
    policyName: decision.policy?.name ?? null,
    violationId: null,
    quarantined: false,
    excepted: false,
  };

  if (!decision.policy || decision.action === PolicyAction.ALLOW) return idle;

  const excepted = await hasLiveException(ctx.orgId, subject.packageVersionId, decision.policy.id);

  const violation = await prisma.policyViolation.create({
    data: {
      orgId: ctx.orgId,
      policyId: decision.policy.id,
      projectId,
      packageVersionId: subject.packageVersionId,
      analysisId: subject.analysisId,
      state: excepted ? ViolationState.EXCEPTED : ViolationState.OPEN,
    },
    select: { id: true },
  });

  let quarantined = false;

  if (decision.action === PolicyAction.BLOCK && !excepted) {
    // One hold per package version per org: a second BLOCK on the same
    // coordinate updates the reason rather than stacking rows.
    await prisma.quarantineItem.upsert({
      where: {
        orgId_packageVersionId: {
          orgId: ctx.orgId,
          packageVersionId: subject.packageVersionId,
        },
      },
      create: {
        orgId: ctx.orgId,
        packageVersionId: subject.packageVersionId,
        reason: `Blocked by policy "${decision.policy.name}"`,
        state: QuarantineState.HELD,
      },
      update: {
        reason: `Blocked by policy "${decision.policy.name}"`,
        state: QuarantineState.HELD,
        reviewedById: null,
        reviewedAt: null,
      },
    });
    quarantined = true;

    await prisma.alert.create({
      data: {
        orgId: ctx.orgId,
        projectId,
        packageVersionId: subject.packageVersionId,
        type: AlertType.QUARANTINE_HELD,
        severity: Severity.HIGH,
        title: `${subject.name}@${subject.version} was held`,
        body: `Policy "${decision.policy.name}" blocked this version. ${decision.policy.conditions
          .map(describeCondition)
          .join('; ')}.`,
      },
    });
  } else {
    await prisma.alert.create({
      data: {
        orgId: ctx.orgId,
        projectId,
        packageVersionId: subject.packageVersionId,
        type: AlertType.POLICY_VIOLATION,
        severity: Severity.MEDIUM,
        title: `${subject.name}@${subject.version} violates "${decision.policy.name}"`,
        body: excepted
          ? 'An approved exception is suppressing enforcement for this version.'
          : decision.policy.conditions.map(describeCondition).join('; '),
      },
    });
  }

  logger.info(
    {
      analysisId,
      orgId: ctx.orgId,
      policyId: decision.policy.id,
      action: decision.action,
      excepted,
    },
    'policy enforced',
  );

  return {
    action: decision.action,
    policyId: decision.policy.id,
    policyName: decision.policy.name,
    violationId: violation.id,
    quarantined,
    excepted,
  };
}
