import { AnalysisStatus, type Prisma, type Role } from '@prisma/client';

import { prisma } from '@/lib/db';
import { platformAdminEmails } from '@/lib/env';
import { ForbiddenError } from '@/lib/errors';
import { HARD_TRIGGERS } from '@/lib/engine/verdict';
import { ENGINE_VERSION } from '@/lib/services/analysis.service';

/**
 * Platform administration — the one surface that reads across tenants.
 *
 * Access is not a role. Roles are granted inside the application, and an
 * application-granted permission that reads every tenant's data is a
 * privilege-escalation path waiting to be found; so the gate is an allowlist of
 * email addresses set on the deployment, which no request can modify.
 * `PLATFORM_ADMIN_EMAILS` empty (the default) closes the surface entirely.
 *
 * Even inside it, the reads are counts and operational state. No analysis
 * evidence, no excerpts, no policy contents, no audit entries belonging to a
 * tenant — an operator needs to know the platform is healthy, not what anyone
 * has been scanning.
 */

export function isPlatformAdmin(email: string): boolean {
  return platformAdminEmails.has(email.trim().toLowerCase());
}

/** Throws unless the caller is on the deployment's allowlist. */
export function assertPlatformAdmin(email: string): void {
  if (!isPlatformAdmin(email)) {
    throw new ForbiddenError('This area is restricted to platform administrators.');
  }
}

export interface PlatformStats {
  organisations: number;
  activeOrganisations: number;
  users: number;
  lockedUsers: number;
  analyses: number;
  analysesLast24h: number;
  queued: number;
  running: number;
  failed: number;
  packages: number;
  packageVersions: number;
  rules: number;
  disabledRules: number;
  corpusEntries: number;
  campaigns: number;
  engineVersion: string;
}

export async function getPlatformStats(): Promise<PlatformStats> {
  const since = new Date(Date.now() - 86_400_000);

  const [
    organisations,
    activeOrganisations,
    users,
    lockedUsers,
    analyses,
    analysesLast24h,
    queued,
    running,
    failed,
    packages,
    packageVersions,
    rules,
    disabledRules,
    corpusEntries,
    campaigns,
  ] = await Promise.all([
    prisma.organization.count(),
    prisma.organization.count({ where: { deletedAt: null } }),
    prisma.user.count(),
    prisma.user.count({ where: { lockedUntil: { gt: new Date() } } }),
    prisma.analysis.count(),
    prisma.analysis.count({ where: { createdAt: { gte: since } } }),
    prisma.analysis.count({ where: { status: AnalysisStatus.QUEUED } }),
    prisma.analysis.count({ where: { status: AnalysisStatus.RUNNING } }),
    prisma.analysis.count({ where: { status: AnalysisStatus.FAILED } }),
    prisma.package.count(),
    prisma.packageVersion.count(),
    prisma.rule.count(),
    prisma.rule.count({ where: { enabled: false } }),
    prisma.corpusEntry.count(),
    prisma.campaign.count(),
  ]);

  return {
    organisations,
    activeOrganisations,
    users,
    lockedUsers,
    analyses,
    analysesLast24h,
    queued,
    running,
    failed,
    packages,
    packageVersions,
    rules,
    disabledRules,
    corpusEntries,
    campaigns,
    engineVersion: ENGINE_VERSION,
  };
}

export interface OrganisationRow {
  id: string;
  name: string;
  slug: string;
  plan: string;
  members: number;
  projects: number;
  analyses: number;
  deletedAt: Date | null;
  createdAt: Date;
}

export async function listOrganisations(): Promise<OrganisationRow[]> {
  const rows = await prisma.organization.findMany({
    include: {
      _count: { select: { memberships: true, projects: true, analyses: true } },
    },
    orderBy: { createdAt: 'desc' },
    take: 200,
  });

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    slug: row.slug,
    plan: row.plan,
    members: row._count.memberships,
    projects: row._count.projects,
    analyses: row._count.analyses,
    deletedAt: row.deletedAt,
    createdAt: row.createdAt,
  }));
}

export interface PlatformUserRow {
  id: string;
  email: string;
  name: string;
  emailVerifiedAt: Date | null;
  totpEnabled: boolean;
  lockedUntil: Date | null;
  lastLoginAt: Date | null;
  organisations: Array<{ name: string; role: Role }>;
  createdAt: Date;
}

export async function listUsers(): Promise<PlatformUserRow[]> {
  const rows = await prisma.user.findMany({
    include: { memberships: { include: { org: { select: { name: true } } } } },
    orderBy: { createdAt: 'desc' },
    take: 200,
  });

  return rows.map((row) => ({
    id: row.id,
    email: row.email,
    name: row.name,
    emailVerifiedAt: row.emailVerifiedAt,
    totpEnabled: row.totpEnabled,
    lockedUntil: row.lockedUntil,
    lastLoginAt: row.lastLoginAt,
    organisations: row.memberships.map((membership) => ({
      name: membership.org.name,
      role: membership.role,
    })),
    createdAt: row.createdAt,
  }));
}

export interface JobRow {
  id: string;
  status: AnalysisStatus;
  ecosystem: string;
  name: string;
  version: string;
  orgName: string;
  startedAt: Date | null;
  createdAt: Date;
  durationMs: number | null;
  errorMessage: string | null;
  /** True for a RUNNING row that has been running longer than the stall window. */
  stalled: boolean;
}

/** Analyses that are not finished, plus recent failures. */
export async function listJobs(stallMs = 15 * 60_000): Promise<JobRow[]> {
  const where: Prisma.AnalysisWhereInput = {
    OR: [
      { status: { in: [AnalysisStatus.QUEUED, AnalysisStatus.RUNNING] } },
      {
        status: AnalysisStatus.FAILED,
        completedAt: { gte: new Date(Date.now() - 86_400_000) },
      },
    ],
  };

  const rows = await prisma.analysis.findMany({
    where,
    include: {
      org: { select: { name: true } },
      packageVersion: {
        select: { version: true, package: { select: { ecosystem: true, name: true } } },
      },
    },
    orderBy: { createdAt: 'desc' },
    take: 200,
  });

  const stallCutoff = Date.now() - stallMs;

  return rows.map((row) => ({
    id: row.id,
    status: row.status,
    ecosystem: row.packageVersion.package.ecosystem,
    name: row.packageVersion.package.name,
    version: row.packageVersion.version,
    orgName: row.org.name,
    startedAt: row.startedAt,
    createdAt: row.createdAt,
    durationMs: row.durationMs,
    errorMessage: row.errorMessage,
    stalled:
      row.status === AnalysisStatus.RUNNING &&
      row.startedAt !== null &&
      row.startedAt.getTime() < stallCutoff,
  }));
}

export interface EngineHealth {
  engineVersion: string;
  hardTriggers: Array<{ id: string; label: string; rationale: string }>;
  rules: Array<{
    ruleId: string;
    family: string;
    severity: string;
    baseWeight: number;
    enabled: boolean;
    firings: number;
  }>;
  latestEval: {
    ranAt: Date;
    precision: number;
    recall: number;
    f1: number;
    falsePositiveRate: number;
    corpusSize: number;
    engineVersion: string;
  } | null;
  /** Platform-wide, deliberately: this is engine behaviour, not tenant data. */
  verdictCounts: Array<{ verdict: string; count: number }>;
}

export async function getEngineHealth(): Promise<EngineHealth> {
  const [rules, firings, latestEval, verdicts] = await Promise.all([
    prisma.rule.findMany({ orderBy: { ruleId: 'asc' } }),
    prisma.signalHit.groupBy({ by: ['ruleId'], _count: { _all: true } }),
    prisma.evalRun.findFirst({ orderBy: { ranAt: 'desc' } }),
    prisma.analysis.groupBy({
      by: ['verdict'],
      where: { verdict: { not: null } },
      _count: { _all: true },
    }),
  ]);

  const firingCounts = new Map(firings.map((row) => [row.ruleId, row._count._all]));

  return {
    engineVersion: ENGINE_VERSION,
    hardTriggers: HARD_TRIGGERS.map((trigger) => ({
      id: trigger.id,
      label: trigger.label,
      rationale: trigger.rationale,
    })),
    rules: rules.map((rule) => ({
      ruleId: rule.ruleId,
      family: rule.family,
      severity: rule.severity,
      baseWeight: rule.baseWeight,
      enabled: rule.enabled,
      firings: firingCounts.get(rule.ruleId) ?? 0,
    })),
    latestEval: latestEval
      ? {
          ranAt: latestEval.ranAt,
          precision: latestEval.precision,
          recall: latestEval.recall,
          f1: latestEval.f1,
          falsePositiveRate: latestEval.falsePositiveRate,
          corpusSize: latestEval.corpusSize,
          engineVersion: latestEval.engineVersion,
        }
      : null,
    verdictCounts: verdicts.map((row) => ({
      verdict: row.verdict ?? 'UNKNOWN',
      count: row._count._all,
    })),
  };
}
