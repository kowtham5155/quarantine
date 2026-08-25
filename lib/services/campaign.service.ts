import { createHash } from 'node:crypto';

import { IndicatorType, type Prisma, type SignalHit } from '@prisma/client';
import { z } from 'zod';

import { prisma } from '@/lib/db';
import { NotFoundError, ValidationError } from '@/lib/errors';
import { logger } from '@/lib/logger';
import { assertCan, type AuthContext } from '@/lib/rbac';
import { verdictRank } from '@/lib/engine/verdict';

/**
 * Campaign clustering: linking separate packages that share an attacker.
 *
 * ## What a campaign is here
 *
 * A campaign is not a judgement about a package — that is what a verdict is
 * for. It is an observation that two analyses produced the *same artefact-level
 * indicator*: the same exfiltration host, the same wallet address, the same
 * byte-identical binary, the same maintainer account behaving the same way.
 * Those are things a package author controls and an attacker reuses, which is
 * exactly what makes them useful for attribution and useless for detection.
 *
 * ## Tenancy
 *
 * Campaigns are org-scoped. The schema allows `orgId: null` for a curated,
 * ecosystem-wide campaign, but nothing here ever writes one: a campaign built
 * out of an org's own scans names the packages that org analysed, and that set
 * is tenant data. Because `Campaign.fingerprint` is globally unique, the org id
 * is folded into the fingerprint — two orgs that independently see the same
 * exfil host each get their own campaign row rather than colliding on one
 * (CLAUDE.md rule 4).
 *
 * ## Why this never fails a scan
 *
 * `runAnalysis` calls `clusterAnalysis` inside its own try/catch. Clustering is
 * an enrichment: an analysis that found real evidence must be recorded even if
 * the clustering pass falls over.
 */

// ---------------------------------------------------------------------------
// Indicator extraction
// ---------------------------------------------------------------------------

/** An attacker-controlled artefact worth clustering on. */
export interface CampaignIndicator {
  type: IndicatorType;
  /**
   * Normalised indicator value.
   *
   * HOSTILE INPUT. Every one of these is derived from package content or
   * registry metadata — a host name, a wallet address, a maintainer handle.
   * It is stored verbatim, compared as an opaque string, and must be escaped
   * on render like any other package-derived string.
   */
  value: string;
  /** Confidence carried over from the signal hit that produced it, 0–1. */
  confidence: number;
  /** Rules that contributed, for the campaign's own evidence trail. */
  ruleIds: string[];
}

/** Verdict at or worse than which an analysis is allowed to seed a campaign. */
const CLUSTERING_VERDICT_FLOOR = 'SUSPICIOUS';

/** Longest indicator value stored. Anything longer is a payload, not an id. */
const MAX_INDICATOR_LENGTH = 255;

/** `https://host/path` or a bare host, as it appears inside a string literal. */
const URL_IN_TEXT = /\bhttps?:\/\/([^\s'"`)\\<>]+)/gi;

/** Hosts that are infrastructure rather than an attacker's own endpoint. */
const UNINTERESTING_HOSTS = new Set([
  'registry.npmjs.org',
  'registry.yarnpkg.com',
  'pypi.org',
  'files.pythonhosted.org',
  'github.com',
  'raw.githubusercontent.com',
  'objects.githubusercontent.com',
  'codeload.github.com',
  'gitlab.com',
  'bitbucket.org',
  'localhost',
  'example.com',
  'www.example.com',
  'schemas.npmjs.com',
  'json-schema.org',
  'www.w3.org',
]);

/**
 * Wallet address shapes.
 *
 * Deliberately narrow. A false indicator does not just add noise, it invents a
 * link between two unrelated packages, which is worse than missing one.
 */
const WALLET_PATTERNS: Array<{ pattern: RegExp; chain: string }> = [
  { pattern: /\b0x[a-fA-F0-9]{40}\b/g, chain: 'evm' },
  { pattern: /\b(?:bc1[a-z0-9]{25,62})\b/g, chain: 'btc' },
  { pattern: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g, chain: 'btc' },
  { pattern: /\bT[a-km-zA-HJ-NP-Z1-9]{33}\b/g, chain: 'tron' },
];

const SHA256_HEX = /^[a-f0-9]{64}$/i;

/** Rules whose evidence names a host or address the package talks to. */
const ENDPOINT_RULES = new Set(['Q-CAP-007', 'Q-CAP-008']);

/**
 * Maintainer rules that describe a *takeover shape* rather than a fact of life.
 *
 * `Q-MNT-004` (sole maintainer on a popular package) is deliberately excluded:
 * it fires on thousands of healthy packages, and clustering on it would file
 * every one-person project under the same "campaign".
 */
const MAINTAINER_RULES = new Set(['Q-MNT-002', 'Q-MNT-003']);

/** Native-binary rule; its evidence carries the file's SHA-256. */
const BINARY_RULES = new Set(['Q-CAP-009']);

type EvidenceDetail = Record<string, unknown>;

function detailOf(hit: Pick<SignalHit, 'evidence'>): EvidenceDetail {
  const { evidence } = hit;
  if (evidence && typeof evidence === 'object' && !Array.isArray(evidence)) {
    return evidence as EvidenceDetail;
  }
  return {};
}

function readString(detail: EvidenceDetail, key: string): string | null {
  const value = detail[key];
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/** Host from a URL, lowercased and stripped of credentials and port. */
export function hostFromUrl(candidate: string): string | null {
  try {
    const url = new URL(candidate);
    const host = url.hostname.toLowerCase();
    return host.length > 0 && host.length <= MAX_INDICATOR_LENGTH ? host : null;
  } catch {
    return null;
  }
}

/**
 * Indicators an analysis contributes, derived only from its persisted hits.
 *
 * Pure: no database, no clock, no network. That is what makes it testable, and
 * clustering is exactly the kind of logic that has to be testable — a bug here
 * asserts a relationship between two strangers' packages.
 */
export function extractIndicators(
  hits: ReadonlyArray<Pick<SignalHit, 'ruleId' | 'excerpt' | 'evidence' | 'confidence'>>,
): CampaignIndicator[] {
  const found = new Map<string, CampaignIndicator>();

  const add = (type: IndicatorType, rawValue: string, ruleId: string, confidence: number): void => {
    const value = rawValue.trim().slice(0, MAX_INDICATOR_LENGTH);
    if (value.length === 0) return;

    const key = `${type}:${value}`;
    const existing = found.get(key);
    if (existing) {
      existing.confidence = Math.max(existing.confidence, confidence);
      if (!existing.ruleIds.includes(ruleId)) existing.ruleIds.push(ruleId);
      return;
    }
    found.set(key, { type, value, confidence, ruleIds: [ruleId] });
  };

  for (const hit of hits) {
    const detail = detailOf(hit);

    // -----------------------------------------------------------------------
    // Exfiltration endpoints
    // -----------------------------------------------------------------------
    if (ENDPOINT_RULES.has(hit.ruleId)) {
      // A literal IPv4 address recorded by Q-CAP-007 is already the indicator.
      const address = readString(detail, 'address');
      if (address) add(IndicatorType.EXFIL_ENDPOINT, address, hit.ruleId, hit.confidence);

      // Q-CAP-008 records a category label ('discord webhook'); the host itself
      // is only in the excerpt, which is a verbatim slice of package source.
      const excerpt = hit.excerpt ?? '';
      URL_IN_TEXT.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = URL_IN_TEXT.exec(excerpt)) !== null) {
        const host = hostFromUrl(match[0]);
        if (!host || UNINTERESTING_HOSTS.has(host)) continue;
        add(IndicatorType.EXFIL_ENDPOINT, host, hit.ruleId, hit.confidence);
      }
    }

    // -----------------------------------------------------------------------
    // Wallet addresses — anywhere in the evidence, not just the wallet rule
    // -----------------------------------------------------------------------
    const excerpt = hit.excerpt ?? '';
    if (excerpt.length > 0) {
      for (const { pattern } of WALLET_PATTERNS) {
        pattern.lastIndex = 0;
        let walletMatch: RegExpExecArray | null;
        while ((walletMatch = pattern.exec(excerpt)) !== null) {
          const raw = walletMatch[0];
          // EVM addresses are case-insensitive (the mixed case is a checksum);
          // base58 chains are not, so only the hex form is folded.
          const value = raw.startsWith('0x') ? raw.toLowerCase() : raw;
          add(IndicatorType.WALLET, value, hit.ruleId, hit.confidence);
        }
      }
    }

    // -----------------------------------------------------------------------
    // Byte-identical payloads
    // -----------------------------------------------------------------------
    if (BINARY_RULES.has(hit.ruleId)) {
      const sha256 = readString(detail, 'sha256');
      if (sha256 && SHA256_HEX.test(sha256)) {
        add(IndicatorType.CODE_HASH, sha256.toLowerCase(), hit.ruleId, hit.confidence);
      }
    }

    // -----------------------------------------------------------------------
    // Maintainer accounts, but only in a takeover-shaped hit
    // -----------------------------------------------------------------------
    if (MAINTAINER_RULES.has(hit.ruleId)) {
      const maintainer = readString(detail, 'maintainer');
      if (maintainer && maintainer !== 'unknown') {
        add(IndicatorType.MAINTAINER, maintainer.toLowerCase(), hit.ruleId, hit.confidence);
      }
    }
  }

  return [...found.values()];
}

/**
 * Stable identity for a campaign.
 *
 * The org id is part of the input, not just a column, so that one org's
 * campaign can never be found — or extended — by another org's scan.
 */
export function campaignFingerprint(
  orgId: string,
  type: IndicatorType,
  value: string,
): string {
  return createHash('sha256').update(`${orgId} ${type} ${value}`).digest('hex');
}

const INDICATOR_LABELS: Record<IndicatorType, string> = {
  [IndicatorType.EXFIL_ENDPOINT]: 'Exfiltration endpoint',
  [IndicatorType.MAINTAINER]: 'Maintainer account',
  [IndicatorType.CODE_HASH]: 'Identical payload',
  [IndicatorType.WALLET]: 'Wallet address',
};

/**
 * Display name for a campaign.
 *
 * Contains package-derived text by construction. It is stored as data and
 * escaped on render like every other hostile string; nothing ever interpolates
 * it into markup, a query or a path.
 */
export function campaignName(type: IndicatorType, value: string): string {
  const shown = value.length > 64 ? `${value.slice(0, 61)}...` : value;
  return `${INDICATOR_LABELS[type]}: ${shown}`;
}

// ---------------------------------------------------------------------------
// Clustering
// ---------------------------------------------------------------------------

export interface ClusterOutcome {
  /** Campaigns this analysis joined, whether newly created or existing. */
  campaignIds: string[];
  indicators: CampaignIndicator[];
  /** Set when the analysis was not eligible to cluster at all. */
  skipped?: 'VERDICT_TOO_LOW' | 'NO_INDICATORS' | 'NOT_COMPLETED';
}

/**
 * Fold one completed analysis into the campaign graph.
 *
 * Gated on the verdict: a CLEAN package that happens to mention a host is not
 * evidence of anything, and clustering on it would fill the graph with
 * coincidences. Only SUSPICIOUS and worse contributes.
 *
 * Authorised with `scan:create` rather than a campaign permission: this is the
 * write half of running a scan, performed on behalf of whoever ran it, and
 * there is no user-facing "create a campaign" action to gate separately.
 */
export async function clusterAnalysis(
  ctx: AuthContext,
  analysisId: string,
): Promise<ClusterOutcome> {
  assertCan(ctx, 'scan:create', { orgId: ctx.orgId });

  const analysis = await prisma.analysis.findFirst({
    where: { id: analysisId, orgId: ctx.orgId },
    select: {
      id: true,
      verdict: true,
      completedAt: true,
      packageVersionId: true,
      signalHits: {
        select: { ruleId: true, excerpt: true, evidence: true, confidence: true },
      },
    },
  });

  if (!analysis) throw new NotFoundError('Analysis not found.');

  if (!analysis.verdict) {
    return { campaignIds: [], indicators: [], skipped: 'NOT_COMPLETED' };
  }

  if (verdictRank(analysis.verdict) > verdictRank(CLUSTERING_VERDICT_FLOOR)) {
    return { campaignIds: [], indicators: [], skipped: 'VERDICT_TOO_LOW' };
  }

  const indicators = extractIndicators(analysis.signalHits);
  if (indicators.length === 0) {
    return { campaignIds: [], indicators: [], skipped: 'NO_INDICATORS' };
  }

  const seenAt = analysis.completedAt ?? new Date();
  const campaignIds: string[] = [];

  for (const indicator of indicators) {
    const campaignId = await joinCampaign(
      ctx.orgId,
      analysis.packageVersionId,
      indicator,
      seenAt,
    );
    campaignIds.push(campaignId);
  }

  logger.info(
    { analysisId, orgId: ctx.orgId, indicators: indicators.length, campaigns: campaignIds.length },
    'analysis clustered',
  );

  return { campaignIds, indicators };
}

/**
 * Attach one package version to the campaign for one indicator, creating the
 * campaign if this is the first time the indicator has been seen.
 *
 * `packageCount` is recounted from the membership rows rather than incremented,
 * so a concurrent second scan of the same package cannot inflate it.
 */
async function joinCampaign(
  orgId: string,
  packageVersionId: string,
  indicator: CampaignIndicator,
  seenAt: Date,
): Promise<string> {
  const fingerprint = campaignFingerprint(orgId, indicator.type, indicator.value);

  return prisma.$transaction(async (tx) => {
    // The sighting window only ever widens. A re-run of an older analysis can
    // arrive after a newer one, so neither end is assumed to move forward.
    const existing = await tx.campaign.findUnique({
      where: { fingerprint },
      select: { firstSeenAt: true, lastSeenAt: true },
    });

    const firstSeenAt = existing && existing.firstSeenAt < seenAt ? existing.firstSeenAt : seenAt;
    const lastSeenAt = existing && existing.lastSeenAt > seenAt ? existing.lastSeenAt : seenAt;

    const campaign = await tx.campaign.upsert({
      where: { fingerprint },
      create: {
        orgId,
        fingerprint,
        name: campaignName(indicator.type, indicator.value),
        description: `Packages sharing ${INDICATOR_LABELS[indicator.type].toLowerCase()} evidence, linked by ${indicator.ruleIds.join(', ')}.`,
        indicatorType: indicator.type,
        indicatorValue: indicator.value,
        firstSeenAt,
        lastSeenAt,
      },
      update: { firstSeenAt, lastSeenAt },
      select: { id: true },
    });

    await tx.campaignMember.upsert({
      where: {
        campaignId_packageVersionId: { campaignId: campaign.id, packageVersionId },
      },
      create: { campaignId: campaign.id, packageVersionId, confidence: indicator.confidence },
      update: { confidence: indicator.confidence },
    });

    const packageCount = await tx.campaignMember.count({ where: { campaignId: campaign.id } });
    await tx.campaign.update({ where: { id: campaign.id }, data: { packageCount } });

    return campaign.id;
  });
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

export const listCampaignsSchema = z.object({
  indicatorType: z.nativeEnum(IndicatorType).optional(),
  /**
   * Include campaigns with a single member. Off by default: a campaign of one
   * is an indicator waiting for a second sighting, not yet a campaign.
   */
  includeSingletons: z.boolean().default(false),
  take: z.number().int().min(1).max(100).default(25),
  skip: z.number().int().min(0).default(0),
});

export type ListCampaignsInput = z.infer<typeof listCampaignsSchema>;

export async function listCampaigns(
  ctx: AuthContext,
  input: Partial<ListCampaignsInput> = {},
) {
  assertCan(ctx, 'campaign:read', { orgId: ctx.orgId });

  const parsed = listCampaignsSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const { indicatorType, includeSingletons, take, skip } = parsed.data;

  const where: Prisma.CampaignWhereInput = {
    orgId: ctx.orgId,
    ...(indicatorType ? { indicatorType } : {}),
    ...(includeSingletons ? {} : { packageCount: { gte: 2 } }),
  };

  const [items, total] = await Promise.all([
    prisma.campaign.findMany({
      where,
      orderBy: [{ lastSeenAt: 'desc' }, { packageCount: 'desc' }],
      take,
      skip,
      select: {
        id: true,
        name: true,
        indicatorType: true,
        indicatorValue: true,
        packageCount: true,
        firstSeenAt: true,
        lastSeenAt: true,
      },
    }),
    prisma.campaign.count({ where }),
  ]);

  return { items, total, take, skip };
}

/** One campaign with its member packages, newest sighting first. */
export async function getCampaign(ctx: AuthContext, campaignId: string) {
  assertCan(ctx, 'campaign:read', { orgId: ctx.orgId });

  const campaign = await prisma.campaign.findFirst({
    where: { id: campaignId, orgId: ctx.orgId },
    include: {
      members: {
        orderBy: { createdAt: 'desc' },
        take: 200,
        include: {
          packageVersion: {
            include: {
              package: { select: { id: true, name: true, ecosystem: true } },
            },
          },
        },
      },
    },
  });

  if (!campaign) throw new NotFoundError('Campaign not found.');
  return campaign;
}

/** Campaigns a given package version belongs to, for its report page. */
export async function campaignsForPackageVersion(
  ctx: AuthContext,
  packageVersionId: string,
) {
  assertCan(ctx, 'campaign:read', { orgId: ctx.orgId });

  const members = await prisma.campaignMember.findMany({
    where: { packageVersionId, campaign: { orgId: ctx.orgId } },
    include: {
      campaign: {
        select: {
          id: true,
          name: true,
          indicatorType: true,
          indicatorValue: true,
          packageCount: true,
          lastSeenAt: true,
        },
      },
    },
    orderBy: { createdAt: 'desc' },
  });

  // A campaign of one is this package on its own; it tells the reader nothing.
  return members.map((member) => member.campaign).filter((campaign) => campaign.packageCount > 1);
}
