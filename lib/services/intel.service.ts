import { AnalysisStatus, Ecosystem, type Prisma, SignalFamily, Verdict } from '@prisma/client';
import { z } from 'zod';

import { VERDICT_META } from '@/lib/constants';
import { prisma } from '@/lib/db';
import { ValidationError } from '@/lib/errors';
import { assertCan, type AuthContext } from '@/lib/rbac';

/**
 * The intelligence feed: what has been flagged recently, across the registry.
 *
 * This is the one read in the application that is deliberately not scoped to a
 * single tenant, and the reasoning is the same as for campaign clustering in
 * phase 4: a supply-chain attack is an ecosystem event, and a tenant that can
 * only see its own scans learns about a compromise when it installs it.
 *
 * What crosses the tenant boundary is kept to the minimum that makes the feed
 * useful, and is stated here so it is a decision rather than an accident:
 *
 *   * Shared: the coordinate (registry, name, version), the worst verdict any
 *     tenant's analysis produced for it, which signal families fired, and when.
 *     All of that is a property of a public artefact — anyone can download the
 *     same tarball and reach the same verdict, because the engine is
 *     deterministic given the bytes.
 *   * Never shared: who scanned it, when they scanned it, how many tenants did,
 *     analysis ids, evidence, excerpts, file paths, or any org-owned record.
 *     `ownedAnalysisId` is populated only from the caller's own analyses.
 *
 * Every package-derived string here is hostile input and is escaped on render.
 */

export const FEED_WINDOWS = [24, 72, 168] as const;
export type FeedWindow = (typeof FEED_WINDOWS)[number];

export const feedQuerySchema = z.object({
  /** Hours of history to consider. */
  windowHours: z.union([z.literal(24), z.literal(72), z.literal(168)]).default(24),
  ecosystem: z.nativeEnum(Ecosystem).optional(),
  /** Restrict to packages this organisation has analysed itself. */
  mineOnly: z.boolean().default(false),
  take: z.number().int().min(1).max(200).default(100),
});

export type FeedQuery = z.infer<typeof feedQuerySchema>;

export interface FeedItem {
  packageVersionId: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  verdict: Verdict;
  families: SignalFamily[];
  /** When the registry published this version, when it says. */
  publishedAt: Date | null;
  /** When the flag was raised. */
  flaggedAt: Date;
  weeklyDownloads: number;
  /** This org's own analysis of the same coordinate, when it has one. */
  ownedAnalysisId: string | null;
}

export interface Feed {
  items: FeedItem[];
  windowHours: number;
  /** Distinct packages flagged in the window, before the display cap. */
  total: number;
  ownedCount: number;
}

const FLAGGED_VERDICTS: Verdict[] = [
  Verdict.SUSPICIOUS,
  Verdict.LIKELY_MALICIOUS,
  Verdict.KNOWN_MALICIOUS,
];

function familiesFrom(value: Prisma.JsonValue): SignalFamily[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return [];
  const families = Object.values(SignalFamily);
  return Object.entries(value as Record<string, unknown>)
    .filter(([key, count]) => families.includes(key as SignalFamily) && Number(count) > 0)
    .map(([key]) => key as SignalFamily);
}

/** Newly flagged package versions, worst verdict first within the window. */
export async function listFeed(
  ctx: AuthContext,
  input: z.input<typeof feedQuerySchema> = {},
): Promise<Feed> {
  // Reading the feed is an analysis read: a viewer may see it, a signed-out
  // visitor may not.
  assertCan(ctx, 'analysis:read', { orgId: ctx.orgId });

  const parsed = feedQuerySchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);
  const { windowHours, ecosystem, mineOnly, take } = parsed.data;

  const since = new Date(Date.now() - windowHours * 3_600_000);

  const where: Prisma.AnalysisWhereInput = {
    status: { in: [AnalysisStatus.COMPLETED, AnalysisStatus.PARTIAL] },
    verdict: { in: FLAGGED_VERDICTS },
    completedAt: { gte: since },
    ...(mineOnly ? { orgId: ctx.orgId } : {}),
    ...(ecosystem ? { packageVersion: { package: { ecosystem } } } : {}),
  };

  // Deliberately selects no org column and no evidence: see the header.
  const rows = await prisma.analysis.findMany({
    where,
    select: {
      verdict: true,
      completedAt: true,
      signalCounts: true,
      packageVersionId: true,
      packageVersion: {
        select: {
          version: true,
          publishedAt: true,
          package: { select: { ecosystem: true, name: true, weeklyDownloads: true } },
        },
      },
    },
    orderBy: { completedAt: 'desc' },
    take: 500,
  });

  // Collapse to one row per coordinate, keeping the worst verdict seen.
  const byVersion = new Map<string, FeedItem>();

  for (const row of rows) {
    if (!row.verdict || !row.completedAt) continue;

    const existing = byVersion.get(row.packageVersionId);
    if (existing && VERDICT_META[existing.verdict].rank <= VERDICT_META[row.verdict].rank) {
      continue;
    }

    byVersion.set(row.packageVersionId, {
      packageVersionId: row.packageVersionId,
      ecosystem: row.packageVersion.package.ecosystem,
      name: row.packageVersion.package.name,
      version: row.packageVersion.version,
      verdict: row.verdict,
      families: familiesFrom(row.signalCounts),
      publishedAt: row.packageVersion.publishedAt,
      flaggedAt: existing ? existing.flaggedAt : row.completedAt,
      weeklyDownloads: row.packageVersion.package.weeklyDownloads,
      ownedAnalysisId: null,
    });
  }

  const items = [...byVersion.values()].sort(
    (a, b) =>
      VERDICT_META[a.verdict].rank - VERDICT_META[b.verdict].rank ||
      b.flaggedAt.getTime() - a.flaggedAt.getTime(),
  );

  const page = items.slice(0, take);

  // Second pass, org-scoped: link each row to the caller's own analysis where
  // one exists, so "we have looked at this" is visible without exposing who
  // else has.
  const owned = await prisma.analysis.findMany({
    where: {
      orgId: ctx.orgId,
      packageVersionId: { in: page.map((item) => item.packageVersionId) },
      verdict: { not: null },
    },
    select: { id: true, packageVersionId: true },
    orderBy: { completedAt: 'desc' },
  });

  const ownedByVersion = new Map<string, string>();
  for (const row of owned) {
    if (!ownedByVersion.has(row.packageVersionId)) {
      ownedByVersion.set(row.packageVersionId, row.id);
    }
  }

  for (const item of page) {
    item.ownedAnalysisId = ownedByVersion.get(item.packageVersionId) ?? null;
  }

  return {
    items: page,
    windowHours,
    total: items.length,
    ownedCount: ownedByVersion.size,
  };
}
