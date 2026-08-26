import { Ecosystem, type Verdict } from '@prisma/client';
import { z } from 'zod';

import { prisma } from '@/lib/db';
import { ValidationError } from '@/lib/errors';
import { assertCan, type AuthContext } from '@/lib/rbac';

/**
 * Global search.
 *
 * Everything reachable from here is either the caller's own tenant data or the
 * global catalogue *restricted to what their org has analysed* — searching the
 * whole registry would turn this box into an oracle for "has anyone scanned
 * this", which the intelligence feed exposes deliberately and search should
 * not.
 *
 * The query is a Prisma `contains` filter, which is parameterised; it is never
 * interpolated into SQL (CLAUDE.md — never `$queryRawUnsafe`).
 */

export const searchSchema = z.object({
  q: z.string().trim().min(2, 'Type at least two characters.').max(120),
  limit: z.number().int().min(1).max(25).default(8),
});

export interface SearchHit {
  kind: 'package' | 'project' | 'policy' | 'campaign' | 'rule' | 'analysis';
  id: string;
  title: string;
  subtitle: string | null;
  href: string;
  /** Verdict badge for package hits. */
  verdict?: Verdict | null;
  ecosystem?: Ecosystem;
}

export interface SearchResults {
  query: string;
  hits: SearchHit[];
  groups: Array<{ kind: SearchHit['kind']; label: string; hits: SearchHit[] }>;
  total: number;
}

const GROUP_LABELS: Record<SearchHit['kind'], string> = {
  package: 'Packages',
  project: 'Projects',
  policy: 'Policies',
  campaign: 'Campaigns',
  rule: 'Rules',
  analysis: 'Analyses',
};

function packageHref(ecosystem: Ecosystem, name: string): string {
  return `/packages/${ecosystem === Ecosystem.NPM ? 'npm' : 'pypi'}/${encodeURIComponent(name)}`;
}

export async function search(
  ctx: AuthContext,
  input: z.input<typeof searchSchema>,
): Promise<SearchResults> {
  assertCan(ctx, 'analysis:read', { orgId: ctx.orgId });

  const parsed = searchSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);
  const { q, limit } = parsed.data;

  const [packages, projects, policies, campaigns, rules] = await Promise.all([
    prisma.package.findMany({
      where: {
        name: { contains: q, mode: 'insensitive' },
        // Only packages this org has actually analysed.
        versions: { some: { analyses: { some: { orgId: ctx.orgId } } } },
      },
      select: {
        id: true,
        name: true,
        ecosystem: true,
        description: true,
        versions: {
          where: { analyses: { some: { orgId: ctx.orgId, verdict: { not: null } } } },
          select: {
            analyses: {
              where: { orgId: ctx.orgId, verdict: { not: null } },
              orderBy: { completedAt: 'desc' },
              take: 1,
              select: { verdict: true },
            },
          },
          take: 1,
        },
      },
      take: limit,
      orderBy: { weeklyDownloads: 'desc' },
    }),
    prisma.project.findMany({
      where: { orgId: ctx.orgId, name: { contains: q, mode: 'insensitive' } },
      select: { id: true, name: true, description: true },
      take: limit,
    }),
    prisma.policy.findMany({
      where: { orgId: ctx.orgId, name: { contains: q, mode: 'insensitive' } },
      select: { id: true, name: true, action: true, enabled: true },
      take: limit,
    }),
    prisma.campaign.findMany({
      where: {
        name: { contains: q, mode: 'insensitive' },
        OR: [{ orgId: null }, { orgId: ctx.orgId }],
      },
      select: { id: true, name: true, indicatorType: true, packageCount: true },
      take: limit,
    }),
    prisma.rule.findMany({
      where: {
        OR: [
          { ruleId: { contains: q, mode: 'insensitive' } },
          { name: { contains: q, mode: 'insensitive' } },
        ],
      },
      select: { ruleId: true, name: true, family: true },
      take: limit,
    }),
  ]);

  const hits: SearchHit[] = [
    ...packages.map((row) => ({
      kind: 'package' as const,
      id: row.id,
      title: row.name,
      subtitle: row.description,
      href: packageHref(row.ecosystem, row.name),
      verdict: row.versions[0]?.analyses[0]?.verdict ?? null,
      ecosystem: row.ecosystem,
    })),
    ...projects.map((row) => ({
      kind: 'project' as const,
      id: row.id,
      title: row.name,
      subtitle: row.description,
      href: `/projects/${row.id}`,
    })),
    ...policies.map((row) => ({
      kind: 'policy' as const,
      id: row.id,
      title: row.name,
      subtitle: `${row.action}${row.enabled ? '' : ' · disabled'}`,
      href: `/policies/${row.id}`,
    })),
    ...campaigns.map((row) => ({
      kind: 'campaign' as const,
      id: row.id,
      title: row.name,
      subtitle: `${row.indicatorType} · ${row.packageCount} packages`,
      href: `/campaigns/${row.id}`,
    })),
    ...rules.map((row) => ({
      kind: 'rule' as const,
      id: row.ruleId,
      title: row.ruleId,
      subtitle: row.name,
      href: `/rules/${row.ruleId}`,
    })),
  ];

  const groups = (['package', 'project', 'policy', 'campaign', 'rule', 'analysis'] as const)
    .map((kind) => ({
      kind,
      label: GROUP_LABELS[kind],
      hits: hits.filter((hit) => hit.kind === kind),
    }))
    .filter((group) => group.hits.length > 0);

  return { query: q, hits, groups, total: hits.length };
}
