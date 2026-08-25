import { AnalysisStatus, SignalFamily, type Ecosystem } from '@prisma/client';

import { prisma } from '@/lib/db';
import { assertCan, type AuthContext } from '@/lib/rbac';
import { isVerdict, VERDICTS, type Verdict } from '@/lib/constants';

/**
 * Dashboard aggregates.
 *
 * Every query filters on `ctx.orgId` (CLAUDE.md rule 4) — including the ones
 * that only produce counts, because a count is a disclosure too: "how many
 * malicious packages has anyone scanned" is not this org's business.
 *
 * The window is fixed at 14 days for the throughput series. Anything longer
 * would want a rollup table rather than a scan of the analyses.
 */

export const THROUGHPUT_DAYS = 14;

export interface VerdictSlice {
  verdict: Verdict;
  count: number;
}

export interface ThroughputPoint {
  /** ISO date, `YYYY-MM-DD`, in UTC. */
  date: string;
  completed: number;
  flagged: number;
}

export interface RecentAnalysis {
  id: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  status: AnalysisStatus;
  verdict: Verdict | null;
  confidence: number | null;
  completedAt: Date | null;
  createdAt: Date;
}

export interface RecentCampaign {
  id: string;
  name: string;
  indicatorType: string;
  packageCount: number;
  lastSeenAt: Date;
}

export interface DashboardSummary {
  packagesAnalysed: number;
  versionsAnalysed: number;
  analysesTotal: number;
  maliciousCount: number;
  suspiciousCount: number;
  openViolations: number;
  quarantineDepth: number;
  queueDepth: number;
  meanDurationMs: number | null;
  p95DurationMs: number | null;
  verdictDistribution: VerdictSlice[];
  familyTotals: Array<{ family: SignalFamily; count: number }>;
  throughput: ThroughputPoint[];
  recentAnalyses: RecentAnalysis[];
  recentCampaigns: RecentCampaign[];
}

function dayKey(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function percentile(sorted: readonly number[], fraction: number): number | null {
  if (sorted.length === 0) return null;
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * fraction) - 1));
  return sorted[index] ?? null;
}

const FLAGGED: Verdict[] = ['KNOWN_MALICIOUS', 'LIKELY_MALICIOUS', 'SUSPICIOUS'];

export async function getDashboardSummary(ctx: AuthContext): Promise<DashboardSummary> {
  assertCan(ctx, 'scan:read', { orgId: ctx.orgId });

  const since = new Date(Date.now() - THROUGHPUT_DAYS * 24 * 60 * 60 * 1000);
  const orgFilter = { orgId: ctx.orgId };

  const [
    analysesTotal,
    verdictGroups,
    distinctPackages,
    distinctVersions,
    openViolations,
    quarantineDepth,
    queueDepth,
    familyGroups,
    window,
    recentAnalyses,
    recentCampaigns,
  ] = await Promise.all([
    prisma.analysis.count({ where: orgFilter }),
    prisma.analysis.groupBy({
      by: ['verdict'],
      where: { ...orgFilter, verdict: { not: null } },
      _count: { _all: true },
    }),
    prisma.package.count({
      where: { versions: { some: { analyses: { some: orgFilter } } } },
    }),
    prisma.packageVersion.count({ where: { analyses: { some: orgFilter } } }),
    prisma.policyViolation.count({ where: { ...orgFilter, state: 'OPEN' } }),
    prisma.quarantineItem.count({ where: { ...orgFilter, state: 'HELD' } }),
    prisma.analysis.count({
      where: { ...orgFilter, status: { in: [AnalysisStatus.QUEUED, AnalysisStatus.RUNNING] } },
    }),
    prisma.signalHit.groupBy({
      by: ['family'],
      where: { analysis: orgFilter },
      _count: { _all: true },
    }),
    prisma.analysis.findMany({
      where: { ...orgFilter, completedAt: { gte: since } },
      select: { completedAt: true, verdict: true, durationMs: true },
      orderBy: { completedAt: 'asc' },
      take: 2000,
    }),
    prisma.analysis.findMany({
      where: orgFilter,
      orderBy: { createdAt: 'desc' },
      take: 8,
      include: { packageVersion: { include: { package: true } } },
    }),
    prisma.campaign.findMany({
      where: { OR: [{ orgId: ctx.orgId }, { orgId: null }] },
      orderBy: { lastSeenAt: 'desc' },
      take: 5,
    }),
  ]);

  const counts = new Map<Verdict, number>();
  for (const group of verdictGroups) {
    if (isVerdict(group.verdict)) counts.set(group.verdict, group._count._all);
  }

  const buckets = new Map<string, ThroughputPoint>();
  for (let offset = THROUGHPUT_DAYS - 1; offset >= 0; offset--) {
    const date = dayKey(new Date(Date.now() - offset * 24 * 60 * 60 * 1000));
    buckets.set(date, { date, completed: 0, flagged: 0 });
  }

  const durations: number[] = [];
  for (const row of window) {
    if (typeof row.durationMs === 'number') durations.push(row.durationMs);
    if (!row.completedAt) continue;
    const bucket = buckets.get(dayKey(row.completedAt));
    if (!bucket) continue;
    bucket.completed += 1;
    if (isVerdict(row.verdict) && FLAGGED.includes(row.verdict)) bucket.flagged += 1;
  }

  durations.sort((a, b) => a - b);
  const mean =
    durations.length > 0
      ? Math.round(durations.reduce((total, value) => total + value, 0) / durations.length)
      : null;

  return {
    packagesAnalysed: distinctPackages,
    versionsAnalysed: distinctVersions,
    analysesTotal,
    maliciousCount: (counts.get('KNOWN_MALICIOUS') ?? 0) + (counts.get('LIKELY_MALICIOUS') ?? 0),
    suspiciousCount: counts.get('SUSPICIOUS') ?? 0,
    openViolations,
    quarantineDepth,
    queueDepth,
    meanDurationMs: mean,
    p95DurationMs: percentile(durations, 0.95),
    verdictDistribution: VERDICTS.map((verdict) => ({
      verdict,
      count: counts.get(verdict) ?? 0,
    })),
    familyTotals: Object.values(SignalFamily).map((family) => ({
      family,
      count: familyGroups.find((group) => group.family === family)?._count._all ?? 0,
    })),
    throughput: [...buckets.values()],
    recentAnalyses: recentAnalyses.map((analysis) => ({
      id: analysis.id,
      ecosystem: analysis.packageVersion.package.ecosystem,
      name: analysis.packageVersion.package.name,
      version: analysis.packageVersion.version,
      status: analysis.status,
      verdict: isVerdict(analysis.verdict) ? analysis.verdict : null,
      confidence: analysis.confidence,
      completedAt: analysis.completedAt,
      createdAt: analysis.createdAt,
    })),
    recentCampaigns: recentCampaigns.map((campaign) => ({
      id: campaign.id,
      name: campaign.name,
      indicatorType: campaign.indicatorType,
      packageCount: campaign.packageCount,
      lastSeenAt: campaign.lastSeenAt,
    })),
  };
}
