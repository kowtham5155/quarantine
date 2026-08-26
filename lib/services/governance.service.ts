import {
  type AlertType,
  type Ecosystem,
  ExceptionState,
  type PolicyAction,
  type Prisma,
  QuarantineState,
  Role,
  type Severity,
  type Verdict,
  ViolationState,
} from '@prisma/client';
import { z } from 'zod';

import { audit } from '@/lib/audit';
import { prisma } from '@/lib/db';
import { ForbiddenError, NotFoundError, ValidationError } from '@/lib/errors';
import { logger } from '@/lib/logger';
import { assertCan, type AuthContext } from '@/lib/rbac';

/**
 * Governance: what happens after a policy fires.
 *
 * Violations are the inbox, quarantine is the hold, exceptions are the
 * time-boxed way out. All three are tenant data and every query here filters on
 * `ctx.orgId` (CLAUDE.md rule 4) — including the bulk operations, where an
 * unfiltered `updateMany` over a list of ids supplied by the client would be a
 * cross-tenant write.
 */

export interface RequestInfo {
  ip?: string | null;
  userAgent?: string | null;
}

const idSchema = z.string().trim().min(1).max(64);
const idListSchema = z.array(idSchema).min(1, 'Select at least one row.').max(200);

// ---------------------------------------------------------------------------
// Shared shapes
// ---------------------------------------------------------------------------

export interface CoordinateRef {
  packageVersionId: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
}

const COORDINATE_INCLUDE = {
  packageVersion: { include: { package: { select: { ecosystem: true, name: true } } } },
} satisfies Prisma.PolicyViolationInclude;

function toCoordinate(row: {
  packageVersionId: string;
  packageVersion: { version: string; package: { ecosystem: Ecosystem; name: string } };
}): CoordinateRef {
  return {
    packageVersionId: row.packageVersionId,
    ecosystem: row.packageVersion.package.ecosystem,
    name: row.packageVersion.package.name,
    version: row.packageVersion.version,
  };
}

// ---------------------------------------------------------------------------
// Violations
// ---------------------------------------------------------------------------

export interface ViolationRow extends CoordinateRef {
  id: string;
  state: ViolationState;
  detectedAt: Date;
  policyId: string;
  policyName: string;
  policyAction: PolicyAction;
  projectId: string | null;
  projectName: string | null;
  analysisId: string | null;
  verdict: Verdict | null;
}

export const listViolationsSchema = z.object({
  state: z.nativeEnum(ViolationState).optional(),
  policyId: idSchema.optional(),
  projectId: idSchema.optional(),
  take: z.number().int().min(1).max(500).default(200),
});

export interface ViolationInbox {
  items: ViolationRow[];
  counts: Record<ViolationState, number>;
  total: number;
  take: number;
}

export async function listViolations(
  ctx: AuthContext,
  input: z.input<typeof listViolationsSchema> = {},
): Promise<ViolationInbox> {
  assertCan(ctx, 'violation:read', { orgId: ctx.orgId });

  const parsed = listViolationsSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);
  const { state, policyId, projectId, take } = parsed.data;

  const where: Prisma.PolicyViolationWhereInput = {
    orgId: ctx.orgId,
    ...(state ? { state } : {}),
    ...(policyId ? { policyId } : {}),
    ...(projectId ? { projectId } : {}),
  };

  const [rows, total, grouped] = await Promise.all([
    prisma.policyViolation.findMany({
      where,
      include: {
        ...COORDINATE_INCLUDE,
        policy: { select: { id: true, name: true, action: true } },
        project: { select: { id: true, name: true } },
        analysis: { select: { id: true, verdict: true } },
      },
      orderBy: { detectedAt: 'desc' },
      take,
    }),
    prisma.policyViolation.count({ where }),
    prisma.policyViolation.groupBy({
      by: ['state'],
      where: { orgId: ctx.orgId },
      _count: { _all: true },
    }),
  ]);

  const counts: Record<ViolationState, number> = {
    [ViolationState.OPEN]: 0,
    [ViolationState.EXCEPTED]: 0,
    [ViolationState.RESOLVED]: 0,
  };
  for (const group of grouped) counts[group.state] = group._count._all;

  return {
    items: rows.map((row) => ({
      ...toCoordinate(row),
      id: row.id,
      state: row.state,
      detectedAt: row.detectedAt,
      policyId: row.policy.id,
      policyName: row.policy.name,
      policyAction: row.policy.action,
      projectId: row.project?.id ?? null,
      projectName: row.project?.name ?? null,
      analysisId: row.analysis?.id ?? null,
      verdict: row.analysis?.verdict ?? null,
    })),
    counts,
    total,
    take,
  };
}

export const triageSchema = z.object({
  violationIds: idListSchema,
  state: z.enum([ViolationState.OPEN, ViolationState.RESOLVED]),
});

/**
 * Bulk triage.
 *
 * EXCEPTED is not settable here on purpose: that state is a consequence of an
 * approved exception, not an opinion an analyst can type in. Moving a row into
 * it by hand would make the exception register lie.
 */
export async function triageViolations(
  ctx: AuthContext & { actorEmail: string },
  input: z.infer<typeof triageSchema>,
  request: RequestInfo = {},
): Promise<{ updated: number }> {
  assertCan(ctx, 'violation:triage', { orgId: ctx.orgId });

  const parsed = triageSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const result = await prisma.policyViolation.updateMany({
    where: { id: { in: parsed.data.violationIds }, orgId: ctx.orgId },
    data: { state: parsed.data.state },
  });

  await audit(
    ctx,
    'violation.triaged',
    { type: 'PolicyViolation', id: null },
    { count: result.count, state: parsed.data.state },
    request,
  );

  return { updated: result.count };
}

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

export interface QuarantineRow extends CoordinateRef {
  id: string;
  reason: string;
  state: QuarantineState;
  heldAt: Date;
  reviewedAt: Date | null;
  reviewedByName: string | null;
  verdict: Verdict | null;
  analysisId: string | null;
  /** Policies whose violation on this coordinate is still open. */
  policyNames: string[];
}

export async function listQuarantine(
  ctx: AuthContext,
  state?: QuarantineState,
): Promise<QuarantineRow[]> {
  assertCan(ctx, 'quarantine:read', { orgId: ctx.orgId });

  const rows = await prisma.quarantineItem.findMany({
    where: { orgId: ctx.orgId, ...(state ? { state } : {}) },
    include: {
      packageVersion: {
        include: {
          package: { select: { ecosystem: true, name: true } },
          // Verdicts are reached through this org's own analyses only.
          analyses: {
            where: { orgId: ctx.orgId, verdict: { not: null } },
            orderBy: { completedAt: 'desc' },
            take: 1,
            select: { id: true, verdict: true },
          },
          policyViolations: {
            where: { orgId: ctx.orgId, state: ViolationState.OPEN },
            select: { policy: { select: { name: true } } },
          },
        },
      },
      reviewedBy: { select: { name: true } },
    },
    orderBy: { createdAt: 'desc' },
  });

  return rows.map((row) => ({
    ...toCoordinate(row),
    id: row.id,
    reason: row.reason,
    state: row.state,
    heldAt: row.createdAt,
    reviewedAt: row.reviewedAt,
    reviewedByName: row.reviewedBy?.name ?? null,
    verdict: row.packageVersion.analyses[0]?.verdict ?? null,
    analysisId: row.packageVersion.analyses[0]?.id ?? null,
    policyNames: [
      ...new Set(row.packageVersion.policyViolations.map((violation) => violation.policy.name)),
    ],
  }));
}

export const reviewQuarantineSchema = z.object({
  itemId: idSchema,
  decision: z.enum([QuarantineState.RELEASED, QuarantineState.CONFIRMED_BAD]),
  note: z.string().trim().max(500).optional(),
});

/**
 * Release a held package or confirm it as bad.
 *
 * Releasing resolves the open violations on that coordinate — the analyst has
 * made the call, and leaving the inbox row open would ask them to make it
 * twice. Confirming keeps them open, because a confirmed-bad package is still
 * a live problem for every project that depends on it.
 */
export async function reviewQuarantineItem(
  ctx: AuthContext & { actorEmail: string },
  input: z.infer<typeof reviewQuarantineSchema>,
  request: RequestInfo = {},
): Promise<void> {
  assertCan(ctx, 'quarantine:review', { orgId: ctx.orgId });

  const parsed = reviewQuarantineSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const item = await prisma.quarantineItem.findFirst({
    where: { id: parsed.data.itemId, orgId: ctx.orgId },
    select: { id: true, packageVersionId: true },
  });
  if (!item) throw new NotFoundError('That quarantine item does not exist.');

  const released = parsed.data.decision === QuarantineState.RELEASED;

  await prisma.$transaction(async (tx) => {
    await tx.quarantineItem.update({
      where: { id: item.id },
      data: {
        state: parsed.data.decision,
        reviewedById: ctx.userId,
        reviewedAt: new Date(),
        ...(parsed.data.note ? { reason: parsed.data.note } : {}),
      },
    });

    if (released) {
      await tx.policyViolation.updateMany({
        where: {
          orgId: ctx.orgId,
          packageVersionId: item.packageVersionId,
          state: ViolationState.OPEN,
        },
        data: { state: ViolationState.RESOLVED },
      });
    }
  });

  await audit(
    ctx,
    released ? 'quarantine.released' : 'quarantine.confirmed_bad',
    { type: 'QuarantineItem', id: item.id },
    { packageVersionId: item.packageVersionId },
    request,
  );
}

// ---------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------

export interface ExceptionRow extends CoordinateRef {
  id: string;
  justification: string;
  state: ExceptionState;
  requestedByName: string;
  requestedById: string;
  approvedByName: string | null;
  policyId: string | null;
  policyName: string | null;
  expiresAt: Date | null;
  createdAt: Date;
  /** True when an approved exception has passed its expiry but not yet been swept. */
  lapsed: boolean;
}

function isLapsed(state: ExceptionState, expiresAt: Date | null): boolean {
  return state === ExceptionState.APPROVED && expiresAt !== null && expiresAt.getTime() <= Date.now();
}

export async function listExceptions(
  ctx: AuthContext,
  state?: ExceptionState,
): Promise<ExceptionRow[]> {
  assertCan(ctx, 'exception:read', { orgId: ctx.orgId });

  const rows = await prisma.exception.findMany({
    where: { orgId: ctx.orgId, ...(state ? { state } : {}) },
    include: {
      packageVersion: { include: { package: { select: { ecosystem: true, name: true } } } },
      requestedBy: { select: { id: true, name: true } },
      approvedBy: { select: { name: true } },
      policy: { select: { id: true, name: true } },
    },
    orderBy: [{ state: 'asc' }, { createdAt: 'desc' }],
  });

  return rows.map((row) => ({
    ...toCoordinate(row),
    id: row.id,
    justification: row.justification,
    state: row.state,
    requestedByName: row.requestedBy.name,
    requestedById: row.requestedBy.id,
    approvedByName: row.approvedBy?.name ?? null,
    policyId: row.policy?.id ?? null,
    policyName: row.policy?.name ?? null,
    expiresAt: row.expiresAt,
    createdAt: row.createdAt,
    lapsed: isLapsed(row.state, row.expiresAt),
  }));
}

export const requestExceptionSchema = z.object({
  packageVersionId: idSchema,
  policyId: idSchema.optional(),
  justification: z
    .string()
    .trim()
    .min(20, 'Explain why this is acceptable — at least a sentence.')
    .max(1000),
  /** Null means indefinite, which an approver has to consciously accept. */
  expiresInDays: z.number().int().min(1).max(365).nullable().default(30),
});

export async function requestException(
  ctx: AuthContext & { actorEmail: string },
  input: z.input<typeof requestExceptionSchema>,
  request: RequestInfo = {},
): Promise<{ id: string }> {
  assertCan(ctx, 'exception:request', { orgId: ctx.orgId });

  const parsed = requestExceptionSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  // The package version must be one this org has actually analysed. Without
  // this check the form would accept any id in the global catalogue and let a
  // caller confirm, by trial, whether a package version exists.
  const reachable = await prisma.analysis.findFirst({
    where: { orgId: ctx.orgId, packageVersionId: parsed.data.packageVersionId },
    select: { id: true },
  });
  if (!reachable) throw new NotFoundError('That package version has not been analysed here.');

  if (parsed.data.policyId) {
    const policy = await prisma.policy.findFirst({
      where: { id: parsed.data.policyId, orgId: ctx.orgId },
      select: { id: true },
    });
    if (!policy) throw new NotFoundError('Policy not found.');
  }

  const pending = await prisma.exception.findFirst({
    where: {
      orgId: ctx.orgId,
      packageVersionId: parsed.data.packageVersionId,
      state: ExceptionState.PENDING,
    },
    select: { id: true },
  });
  if (pending) {
    throw new ValidationError('There is already a pending request for that package version.');
  }

  const created = await prisma.exception.create({
    data: {
      orgId: ctx.orgId,
      packageVersionId: parsed.data.packageVersionId,
      policyId: parsed.data.policyId ?? null,
      justification: parsed.data.justification,
      requestedById: ctx.userId,
      expiresAt:
        parsed.data.expiresInDays === null
          ? null
          : new Date(Date.now() + parsed.data.expiresInDays * 86_400_000),
      state: ExceptionState.PENDING,
    },
    select: { id: true },
  });

  await audit(
    ctx,
    'exception.requested',
    { type: 'Exception', id: created.id },
    { packageVersionId: parsed.data.packageVersionId },
    request,
  );

  return created;
}

export const decideExceptionSchema = z.object({
  exceptionId: idSchema,
  decision: z.enum([ExceptionState.APPROVED, ExceptionState.DENIED]),
});

/**
 * Approve or deny a request.
 *
 * `assertCan` is given the requester as the resource owner, which is what makes
 * the "nobody approves their own request" rule in lib/rbac.ts fire. Approving
 * marks the matching open violations EXCEPTED and lifts any quarantine hold on
 * the coordinate; the hold comes back the next time the policy fires, once the
 * exception has expired.
 */
export async function decideException(
  ctx: AuthContext & { actorEmail: string },
  input: z.infer<typeof decideExceptionSchema>,
  request: RequestInfo = {},
): Promise<void> {
  const parsed = decideExceptionSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const row = await prisma.exception.findFirst({
    where: { id: parsed.data.exceptionId, orgId: ctx.orgId },
    select: { id: true, requestedById: true, packageVersionId: true, policyId: true, state: true },
  });
  if (!row) throw new NotFoundError('That exception request does not exist.');

  assertCan(ctx, 'exception:approve', { orgId: ctx.orgId, ownerId: row.requestedById });

  if (row.state !== ExceptionState.PENDING) {
    throw new ValidationError('That request has already been decided.');
  }

  const approved = parsed.data.decision === ExceptionState.APPROVED;

  await prisma.$transaction(async (tx) => {
    await tx.exception.update({
      where: { id: row.id },
      data: { state: parsed.data.decision, approvedById: ctx.userId },
    });

    if (!approved) return;

    await tx.policyViolation.updateMany({
      where: {
        orgId: ctx.orgId,
        packageVersionId: row.packageVersionId,
        state: ViolationState.OPEN,
        ...(row.policyId ? { policyId: row.policyId } : {}),
      },
      data: { state: ViolationState.EXCEPTED },
    });

    await tx.quarantineItem.updateMany({
      where: {
        orgId: ctx.orgId,
        packageVersionId: row.packageVersionId,
        state: QuarantineState.HELD,
      },
      data: {
        state: QuarantineState.RELEASED,
        reviewedById: ctx.userId,
        reviewedAt: new Date(),
        reason: 'Released by an approved exception',
      },
    });
  });

  await audit(
    ctx,
    approved ? 'exception.approved' : 'exception.denied',
    { type: 'Exception', id: row.id },
    { packageVersionId: row.packageVersionId },
    request,
  );
}

/**
 * Move approved exceptions that have passed their expiry into EXPIRED, and
 * reopen the violations they were suppressing.
 *
 * Enforcement never depends on this having run — `hasLiveException` compares
 * against the clock on every evaluation — so this is bookkeeping that makes the
 * register honest, not a control. Cron calls it; the exceptions page calls it
 * too, so a stale row cannot sit there looking live.
 */
export async function sweepExpiredExceptions(
  ctx: AuthContext & { actorEmail: string },
): Promise<{ expired: number }> {
  const now = new Date();

  const lapsed = await prisma.exception.findMany({
    where: {
      orgId: ctx.orgId,
      state: ExceptionState.APPROVED,
      expiresAt: { not: null, lte: now },
    },
    select: { id: true, packageVersionId: true, policyId: true },
  });

  if (lapsed.length === 0) return { expired: 0 };

  await prisma.$transaction(async (tx) => {
    await tx.exception.updateMany({
      where: { id: { in: lapsed.map((row) => row.id) }, orgId: ctx.orgId },
      data: { state: ExceptionState.EXPIRED },
    });

    for (const row of lapsed) {
      await tx.policyViolation.updateMany({
        where: {
          orgId: ctx.orgId,
          packageVersionId: row.packageVersionId,
          state: ViolationState.EXCEPTED,
          ...(row.policyId ? { policyId: row.policyId } : {}),
        },
        data: { state: ViolationState.OPEN },
      });
    }
  });

  logger.info({ orgId: ctx.orgId, expired: lapsed.length }, 'exceptions expired');

  await audit(
    ctx,
    'exception.expired',
    { type: 'Exception', id: null },
    { count: lapsed.length },
    {},
  );

  return { expired: lapsed.length };
}

/** Exceptions inside their last week, for the alert the dashboard raises. */
export async function expiringSoon(ctx: AuthContext, withinDays = 7): Promise<ExceptionRow[]> {
  const all = await listExceptions(ctx, ExceptionState.APPROVED);
  const cutoff = Date.now() + withinDays * 86_400_000;

  return all.filter(
    (row) => row.expiresAt !== null && !row.lapsed && row.expiresAt.getTime() <= cutoff,
  );
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

export interface AlertRow {
  id: string;
  type: AlertType;
  severity: Severity;
  title: string;
  /** HOSTILE INPUT: may quote a package-derived string. Escape on render. */
  body: string;
  readAt: Date | null;
  resolvedAt: Date | null;
  createdAt: Date;
  projectId: string | null;
  projectName: string | null;
  coordinate: CoordinateRef | null;
}

export async function listAlerts(
  ctx: AuthContext,
  input: { resolved?: boolean; take?: number } = {},
): Promise<{ items: AlertRow[]; unresolved: number; unread: number }> {
  assertCan(ctx, 'alert:read', { orgId: ctx.orgId });

  const take = Math.min(Math.max(input.take ?? 200, 1), 500);

  const [rows, unresolved, unread] = await Promise.all([
    prisma.alert.findMany({
      where: {
        orgId: ctx.orgId,
        ...(input.resolved === undefined
          ? {}
          : input.resolved
            ? { resolvedAt: { not: null } }
            : { resolvedAt: null }),
      },
      include: {
        project: { select: { id: true, name: true } },
        packageVersion: {
          include: { package: { select: { ecosystem: true, name: true } } },
        },
      },
      orderBy: { createdAt: 'desc' },
      take,
    }),
    prisma.alert.count({ where: { orgId: ctx.orgId, resolvedAt: null } }),
    prisma.alert.count({ where: { orgId: ctx.orgId, readAt: null } }),
  ]);

  return {
    items: rows.map((row) => ({
      id: row.id,
      type: row.type,
      severity: row.severity,
      title: row.title,
      body: row.body,
      readAt: row.readAt,
      resolvedAt: row.resolvedAt,
      createdAt: row.createdAt,
      projectId: row.project?.id ?? null,
      projectName: row.project?.name ?? null,
      coordinate: row.packageVersion
        ? {
            packageVersionId: row.packageVersion.id,
            ecosystem: row.packageVersion.package.ecosystem,
            name: row.packageVersion.package.name,
            version: row.packageVersion.version,
          }
        : null,
    })),
    unresolved,
    unread,
  };
}

export const resolveAlertsSchema = z.object({
  alertIds: idListSchema,
  resolved: z.boolean().default(true),
});

export async function resolveAlerts(
  ctx: AuthContext & { actorEmail: string },
  input: z.input<typeof resolveAlertsSchema>,
  request: RequestInfo = {},
): Promise<{ updated: number }> {
  assertCan(ctx, 'alert:resolve', { orgId: ctx.orgId });

  const parsed = resolveAlertsSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const now = new Date();
  const result = await prisma.alert.updateMany({
    where: { id: { in: parsed.data.alertIds }, orgId: ctx.orgId },
    data: parsed.data.resolved ? { resolvedAt: now, readAt: now } : { resolvedAt: null },
  });

  await audit(
    ctx,
    'alert.resolved',
    { type: 'Alert', id: null },
    { count: result.count, resolved: parsed.data.resolved },
    request,
  );

  return { updated: result.count };
}

/** Mark everything currently visible as read. Not privileged, so not audited. */
export async function markAlertsRead(ctx: AuthContext): Promise<void> {
  assertCan(ctx, 'alert:read', { orgId: ctx.orgId });

  await prisma.alert.updateMany({
    where: { orgId: ctx.orgId, readAt: null },
    data: { readAt: new Date() },
  });
}

/** Guard for surfaces an analyst may see but only an admin may change. */
export function assertApprover(ctx: AuthContext): void {
  if (ctx.role !== Role.ADMIN && ctx.role !== Role.OWNER) {
    throw new ForbiddenError('Only an administrator can decide exception requests.');
  }
}
