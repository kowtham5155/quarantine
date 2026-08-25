import { AnalysisStatus, Ecosystem, Severity, SignalFamily, type Prisma } from '@prisma/client';
import { z } from 'zod';

import { prisma } from '@/lib/db';
import { NotFoundError, ValidationError } from '@/lib/errors';
import { assertCan, type AuthContext } from '@/lib/rbac';
import { isVerdict, type Verdict } from '@/lib/constants';
import { HARD_TRIGGERS } from '@/lib/engine/verdict';

/**
 * Package intelligence: the read side of the catalogue.
 *
 * The catalogue itself (Package, PackageVersion, Rule) is deliberately global —
 * two orgs analysing `left-pad` are looking at the same tarball. Verdicts are
 * not: an Analysis belongs to exactly one org, and every query here reaches the
 * catalogue *through* an org-scoped analysis (CLAUDE.md rules 3 and 4). An org
 * therefore only ever sees packages it has actually analysed, and only its own
 * verdicts for them.
 *
 * Everything returned from here that originated in a package — names, versions,
 * descriptions, file paths, excerpts, maintainer handles, repository URLs — is
 * hostile input. It is returned as data and escaped at the render boundary.
 */

// ---------------------------------------------------------------------------
// Shared shapes
// ---------------------------------------------------------------------------

/** The org's most recent analysis of one version, flattened for display. */
export interface VersionVerdict {
  analysisId: string;
  status: AnalysisStatus;
  verdict: Verdict | null;
  confidence: number | null;
  weightedScore: number | null;
  hardTriggersFired: string[];
  completedAt: Date | null;
  durationMs: number | null;
  signalCounts: Record<string, number>;
}

export interface PackageListItem {
  id: string;
  ecosystem: Ecosystem;
  name: string;
  description: string | null;
  latestVersion: string | null;
  repositoryUrl: string | null;
  weeklyDownloads: number;
  maintainerCount: number;
  isDeprecated: boolean;
  versionsAnalysed: number;
  /** Worst verdict the org has seen across every version it analysed. */
  worstVerdict: Verdict | null;
  /** Verdict of the most recently completed analysis. */
  latestVerdict: Verdict | null;
  lastAnalysedAt: Date | null;
  /** Families that fired at least once, across the org's analyses. */
  families: SignalFamily[];
}

const VERDICT_RANK: Record<Verdict, number> = {
  KNOWN_MALICIOUS: 0,
  LIKELY_MALICIOUS: 1,
  SUSPICIOUS: 2,
  LOW_RISK: 3,
  CLEAN: 4,
};

function worstOf(verdicts: ReadonlyArray<Verdict | null>): Verdict | null {
  let worst: Verdict | null = null;
  for (const verdict of verdicts) {
    if (!verdict) continue;
    if (!worst || VERDICT_RANK[verdict] < VERDICT_RANK[worst]) worst = verdict;
  }
  return worst;
}

function asVerdict(value: string | null): Verdict | null {
  return isVerdict(value) ? value : null;
}

/** `signalCounts` is a Json column; narrow it to the shape the UI expects. */
function toSignalCounts(value: Prisma.JsonValue): Record<string, number> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const out: Record<string, number> = {};
  for (const [key, count] of Object.entries(value)) {
    if (typeof count === 'number' && Number.isFinite(count)) out[key] = count;
  }
  return out;
}

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

export const listPackagesSchema = z.object({
  ecosystem: z.nativeEnum(Ecosystem).optional(),
  verdict: z.string().optional(),
  family: z.nativeEnum(SignalFamily).optional(),
  search: z.string().trim().max(214).optional(),
  take: z.number().int().min(1).max(200).default(100),
  skip: z.number().int().min(0).default(0),
});

export type ListPackagesInput = z.infer<typeof listPackagesSchema>;

export interface PackageListPage {
  items: PackageListItem[];
  total: number;
  take: number;
  skip: number;
}

/** Every package this org has analysed, with the org's own verdicts. */
export async function listPackages(
  ctx: AuthContext,
  input: Partial<ListPackagesInput> = {},
): Promise<PackageListPage> {
  assertCan(ctx, 'scan:read', { orgId: ctx.orgId });

  const parsed = listPackagesSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);
  const { ecosystem, verdict, family, search, take, skip } = parsed.data;

  const analysisFilter: Prisma.AnalysisWhereInput = {
    orgId: ctx.orgId,
    ...(isVerdict(verdict) ? { verdict } : {}),
    ...(family ? { signalHits: { some: { family } } } : {}),
  };

  const where: Prisma.PackageWhereInput = {
    ...(ecosystem ? { ecosystem } : {}),
    ...(search ? { name: { contains: search, mode: 'insensitive' } } : {}),
    versions: { some: { analyses: { some: analysisFilter } } },
  };

  const [rows, total] = await Promise.all([
    prisma.package.findMany({
      where,
      orderBy: [{ weeklyDownloads: 'desc' }, { name: 'asc' }],
      take,
      skip,
      include: {
        versions: {
          select: {
            version: true,
            analyses: {
              where: { orgId: ctx.orgId },
              orderBy: { createdAt: 'desc' },
              take: 1,
              select: {
                verdict: true,
                completedAt: true,
                signalCounts: true,
                signalHits: { select: { family: true }, distinct: ['family'] },
              },
            },
          },
        },
      },
    }),
    prisma.package.count({ where }),
  ]);

  return {
    items: rows.map((row) => {
      const analysed = row.versions.flatMap((version) => version.analyses);
      const families = new Set<SignalFamily>();
      for (const analysis of analysed) {
        for (const hit of analysis.signalHits) families.add(hit.family);
      }

      const completed = analysed
        .filter((analysis) => analysis.completedAt !== null)
        .sort((a, b) => (b.completedAt?.getTime() ?? 0) - (a.completedAt?.getTime() ?? 0));
      const latest = completed[0];

      return {
        id: row.id,
        ecosystem: row.ecosystem,
        name: row.name,
        description: row.description,
        latestVersion: row.latestVersion,
        repositoryUrl: row.repositoryUrl,
        weeklyDownloads: row.weeklyDownloads,
        maintainerCount: row.maintainerCount,
        isDeprecated: row.isDeprecated,
        versionsAnalysed: analysed.length,
        worstVerdict: worstOf(analysed.map((analysis) => asVerdict(analysis.verdict))),
        latestVerdict: asVerdict(latest?.verdict ?? null),
        lastAnalysedAt: latest?.completedAt ?? null,
        families: [...families],
      };
    }),
    total,
    take,
    skip,
  };
}

// ---------------------------------------------------------------------------
// Package overview
// ---------------------------------------------------------------------------

export interface PackageVersionRow {
  id: string;
  version: string;
  publishedAt: Date | null;
  unpackedSize: number | null;
  fileCount: number | null;
  hasInstallScripts: boolean;
  provenanceAttested: boolean;
  integrity: string | null;
  latest: VersionVerdict | null;
}

export interface MaintainerEventRow {
  id: string;
  type: 'ADDED' | 'REMOVED' | 'PUBLISHED';
  actor: string;
  occurredAt: Date;
  metadata: Record<string, unknown>;
}

export interface PackageOverview {
  id: string;
  ecosystem: Ecosystem;
  name: string;
  description: string | null;
  latestVersion: string | null;
  repositoryUrl: string | null;
  weeklyDownloads: number;
  maintainerCount: number;
  isDeprecated: boolean;
  firstPublishedAt: Date | null;
  versions: PackageVersionRow[];
  maintainerEvents: MaintainerEventRow[];
  worstVerdict: Verdict | null;
  maintainers: string[];
}

function toMetadata(value: Prisma.JsonValue): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function toVersionVerdict(analysis: {
  id: string;
  status: AnalysisStatus;
  verdict: string | null;
  confidence: number | null;
  weightedScore: number | null;
  hardTriggersFired: string[];
  completedAt: Date | null;
  durationMs: number | null;
  signalCounts: Prisma.JsonValue;
}): VersionVerdict {
  return {
    analysisId: analysis.id,
    status: analysis.status,
    verdict: asVerdict(analysis.verdict),
    confidence: analysis.confidence,
    weightedScore: analysis.weightedScore,
    hardTriggersFired: analysis.hardTriggersFired,
    completedAt: analysis.completedAt,
    durationMs: analysis.durationMs,
    signalCounts: toSignalCounts(analysis.signalCounts),
  };
}

/** One package, every version, with the org's latest verdict per version. */
export async function getPackageOverview(
  ctx: AuthContext,
  ecosystem: Ecosystem,
  name: string,
): Promise<PackageOverview> {
  assertCan(ctx, 'scan:read', { orgId: ctx.orgId });

  const row = await prisma.package.findUnique({
    where: { ecosystem_name: { ecosystem, name } },
    include: {
      versions: {
        orderBy: [{ publishedAt: 'desc' }, { version: 'desc' }],
        include: {
          analyses: {
            where: { orgId: ctx.orgId },
            orderBy: { createdAt: 'desc' },
            take: 1,
          },
        },
      },
      maintainerEvents: { orderBy: { occurredAt: 'desc' }, take: 100 },
    },
  });

  if (!row) throw new NotFoundError('That package has not been analysed here yet.');

  const versions: PackageVersionRow[] = row.versions.map((version) => {
    const latest = version.analyses[0];
    return {
      id: version.id,
      version: version.version,
      publishedAt: version.publishedAt,
      unpackedSize: version.unpackedSize,
      fileCount: version.fileCount,
      hasInstallScripts: version.hasInstallScripts,
      provenanceAttested: version.provenanceAttested,
      integrity: version.integrity,
      latest: latest ? toVersionVerdict(latest) : null,
    };
  });

  const maintainers = [
    ...new Set(
      row.maintainerEvents.filter((event) => event.type !== 'REMOVED').map((event) => event.actor),
    ),
  ];

  return {
    id: row.id,
    ecosystem: row.ecosystem,
    name: row.name,
    description: row.description,
    latestVersion: row.latestVersion,
    repositoryUrl: row.repositoryUrl,
    weeklyDownloads: row.weeklyDownloads,
    maintainerCount: row.maintainerCount,
    isDeprecated: row.isDeprecated,
    firstPublishedAt: row.firstPublishedAt,
    versions,
    maintainerEvents: row.maintainerEvents.map((event) => ({
      id: event.id,
      type: event.type,
      actor: event.actor,
      occurredAt: event.occurredAt,
      metadata: toMetadata(event.metadata),
    })),
    worstVerdict: worstOf(versions.map((version) => version.latest?.verdict ?? null)),
    maintainers,
  };
}

// ---------------------------------------------------------------------------
// Version report
// ---------------------------------------------------------------------------

export interface RuleMeta {
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
}

export interface SignalHitRow {
  id: string;
  ruleId: string;
  family: SignalFamily;
  severity: Severity;
  weight: number;
  confidence: number;
  contextModifier: number;
  filePath: string | null;
  lineStart: number | null;
  lineEnd: number | null;
  /** HOSTILE INPUT: a verbatim slice of the analysed package. Escape on render. */
  excerpt: string | null;
  evidence: Record<string, unknown>;
}

export interface ProvenanceRow {
  status: 'MATCH' | 'DIVERGENT' | 'NO_REPO' | 'REPO_UNREACHABLE' | 'NO_TAG';
  repoUrl: string | null;
  gitRef: string | null;
  filesOnlyInTarball: string[];
  filesOnlyInRepo: string[];
  modifiedFiles: string[];
  diffSummary: Record<string, unknown>;
}

export interface TyposquatRow {
  targetPackage: string;
  distance: number;
  technique: string;
  similarity: number;
  targetDownloads: number;
}

export interface FamilyBreakdown {
  family: SignalFamily;
  /** Rules in the catalogue for this family that were enabled at scan time. */
  evaluated: number;
  fired: number;
  /** Sum of weight x confidence x contextModifier for the rules that fired. */
  contribution: number;
  worstSeverity: Severity | null;
}

export interface VersionReport {
  package: {
    id: string;
    ecosystem: Ecosystem;
    name: string;
    description: string | null;
    repositoryUrl: string | null;
    weeklyDownloads: number;
    maintainerCount: number;
    isDeprecated: boolean;
    latestVersion: string | null;
  };
  version: {
    id: string;
    version: string;
    publishedAt: Date | null;
    unpackedSize: number | null;
    fileCount: number | null;
    hasInstallScripts: boolean;
    provenanceAttested: boolean;
    integrity: string | null;
    tarballUrl: string | null;
  };
  analysis: VersionVerdict & {
    engineVersion: string;
    startedAt: Date | null;
    createdAt: Date;
    filesAnalysed: number;
    errorMessage: string | null;
  };
  hardTriggers: Array<{ id: string; label: string; rationale: string }>;
  hits: SignalHitRow[];
  /** Every rule in the catalogue, keyed by rule id — including ones that did not fire. */
  rules: RuleMeta[];
  families: FamilyBreakdown[];
  provenance: ProvenanceRow | null;
  typosquats: TyposquatRow[];
  /** Other versions of this package the org has analysed, newest first. */
  siblingVersions: Array<{ version: string; verdict: Verdict | null; publishedAt: Date | null }>;
}

function toEvidence(value: Prisma.JsonValue): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

export async function loadRuleMeta(): Promise<RuleMeta[]> {
  const rules = await prisma.rule.findMany({ orderBy: { ruleId: 'asc' } });
  return rules.map((rule) => ({
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
  }));
}

/**
 * The org's most recent analysis of one package version, with everything the
 * report pages need.
 *
 * A QUEUED or RUNNING analysis is returned too — the report page renders it as
 * in-progress rather than pretending the version has never been looked at.
 */
export async function getVersionReport(
  ctx: AuthContext,
  ecosystem: Ecosystem,
  name: string,
  version: string,
): Promise<VersionReport> {
  assertCan(ctx, 'scan:read', { orgId: ctx.orgId });

  const analysis = await prisma.analysis.findFirst({
    where: {
      orgId: ctx.orgId,
      packageVersion: { version, package: { ecosystem, name } },
    },
    orderBy: [{ completedAt: 'desc' }, { createdAt: 'desc' }],
    include: {
      packageVersion: { include: { package: true } },
      signalHits: { orderBy: [{ weight: 'desc' }, { ruleId: 'asc' }] },
      provenanceChecks: { orderBy: { createdAt: 'desc' }, take: 1 },
      typosquatMatches: { orderBy: { distance: 'asc' } },
    },
  });

  if (!analysis) {
    throw new NotFoundError('That version has not been analysed by this organisation.');
  }

  const [rules, siblings] = await Promise.all([
    loadRuleMeta(),
    prisma.packageVersion.findMany({
      where: {
        package: { ecosystem, name },
        analyses: { some: { orgId: ctx.orgId } },
      },
      orderBy: [{ publishedAt: 'desc' }, { version: 'desc' }],
      take: 50,
      select: {
        version: true,
        publishedAt: true,
        analyses: {
          where: { orgId: ctx.orgId },
          orderBy: { createdAt: 'desc' },
          take: 1,
          select: { verdict: true },
        },
      },
    }),
  ]);

  const hits: SignalHitRow[] = analysis.signalHits.map((hit) => ({
    id: hit.id,
    ruleId: hit.ruleId,
    family: hit.family,
    severity: hit.severity,
    weight: hit.weight,
    confidence: hit.confidence,
    contextModifier: hit.contextModifier,
    filePath: hit.filePath,
    lineStart: hit.lineStart,
    lineEnd: hit.lineEnd,
    excerpt: hit.excerpt,
    evidence: toEvidence(hit.evidence),
  }));

  const provenanceRow = analysis.provenanceChecks[0];
  const pkg = analysis.packageVersion.package;

  return {
    package: {
      id: pkg.id,
      ecosystem: pkg.ecosystem,
      name: pkg.name,
      description: pkg.description,
      repositoryUrl: pkg.repositoryUrl,
      weeklyDownloads: pkg.weeklyDownloads,
      maintainerCount: pkg.maintainerCount,
      isDeprecated: pkg.isDeprecated,
      latestVersion: pkg.latestVersion,
    },
    version: {
      id: analysis.packageVersion.id,
      version: analysis.packageVersion.version,
      publishedAt: analysis.packageVersion.publishedAt,
      unpackedSize: analysis.packageVersion.unpackedSize,
      fileCount: analysis.packageVersion.fileCount,
      hasInstallScripts: analysis.packageVersion.hasInstallScripts,
      provenanceAttested: analysis.packageVersion.provenanceAttested,
      integrity: analysis.packageVersion.integrity,
      tarballUrl: analysis.packageVersion.tarballUrl,
    },
    analysis: {
      ...toVersionVerdict(analysis),
      engineVersion: analysis.engineVersion,
      startedAt: analysis.startedAt,
      createdAt: analysis.createdAt,
      filesAnalysed: analysis.filesAnalysed,
      errorMessage: analysis.errorMessage,
    },
    hardTriggers: hardTriggerDetail(analysis.hardTriggersFired),
    hits,
    rules,
    families: familyBreakdown(rules, hits),
    provenance: provenanceRow
      ? {
          status: provenanceRow.status,
          repoUrl: provenanceRow.repoUrl,
          gitRef: provenanceRow.gitRef,
          filesOnlyInTarball: provenanceRow.filesOnlyInTarball,
          filesOnlyInRepo: provenanceRow.filesOnlyInRepo,
          modifiedFiles: provenanceRow.modifiedFiles,
          diffSummary: toEvidence(provenanceRow.diffSummary),
        }
      : null,
    typosquats: analysis.typosquatMatches.map((match) => ({
      targetPackage: match.targetPackage,
      distance: match.distance,
      technique: match.technique,
      similarity: match.similarity,
      targetDownloads: match.targetDownloads,
    })),
    siblingVersions: siblings.map((sibling) => ({
      version: sibling.version,
      verdict: asVerdict(sibling.analyses[0]?.verdict ?? null),
      publishedAt: sibling.publishedAt,
    })),
  };
}

/** Per-family counts and score contribution, for the report's breakdown chart. */
export function familyBreakdown(
  rules: readonly RuleMeta[],
  hits: readonly SignalHitRow[],
): FamilyBreakdown[] {
  return Object.values(SignalFamily).map((family) => {
    const familyHits = hits.filter((hit) => hit.family === family);
    const firedRules = new Set(familyHits.map((hit) => hit.ruleId));

    // One rule can produce many hits (one per piece of evidence); the score is
    // the rule's contribution once, not once per line it matched.
    let contribution = 0;
    for (const ruleId of firedRules) {
      const hit = familyHits.find((candidate) => candidate.ruleId === ruleId);
      if (hit) contribution += hit.weight * hit.confidence * hit.contextModifier;
    }

    let worstSeverity: Severity | null = null;
    for (const hit of familyHits) {
      if (!worstSeverity || SEVERITY_RANK[hit.severity] < SEVERITY_RANK[worstSeverity]) {
        worstSeverity = hit.severity;
      }
    }

    return {
      family,
      evaluated: rules.filter((rule) => rule.family === family && rule.enabled).length,
      fired: firedRules.size,
      contribution: Math.round(contribution * 100) / 100,
      worstSeverity,
    };
  });
}

/** Label and rationale for each hard trigger id recorded on an analysis. */
export function hardTriggerDetail(
  ids: readonly string[],
): Array<{ id: string; label: string; rationale: string }> {
  return ids.flatMap((id) => {
    const trigger = HARD_TRIGGERS.find((candidate) => candidate.id === id);
    return trigger ? [{ id, label: trigger.label, rationale: trigger.rationale }] : [];
  });
}

// ---------------------------------------------------------------------------
// File inventory
// ---------------------------------------------------------------------------

export interface FileRiskRow {
  path: string;
  families: SignalFamily[];
  ruleIds: string[];
  hits: SignalHitRow[];
  /** Sum of weight x confidence x modifier over the distinct rules touching this file. */
  risk: number;
  worstSeverity: Severity;
  flaggedLines: number;
}

/**
 * The files a report can talk about, ranked by risk.
 *
 * Quarantine does not retain package contents: the tarball is extracted into a
 * per-scan temp directory that is deleted in a `finally` block before the
 * analysis returns (THE SAFETY RULE). What survives is the evidence — a path, a
 * line range and a short excerpt per hit — so this inventory covers the files
 * that at least one rule pointed at, not every file in the archive. The page
 * says so rather than implying a complete tree.
 */
export function fileInventory(hits: readonly SignalHitRow[]): FileRiskRow[] {
  const byPath = new Map<string, SignalHitRow[]>();

  for (const hit of hits) {
    if (!hit.filePath) continue;
    const existing = byPath.get(hit.filePath);
    if (existing) existing.push(hit);
    else byPath.set(hit.filePath, [hit]);
  }

  const rows: FileRiskRow[] = [];

  for (const [path, fileHits] of byPath) {
    const ruleIds = [...new Set(fileHits.map((hit) => hit.ruleId))].sort();
    const families = [...new Set(fileHits.map((hit) => hit.family))];

    let risk = 0;
    for (const ruleId of ruleIds) {
      const hit = fileHits.find((candidate) => candidate.ruleId === ruleId);
      if (hit) risk += hit.weight * hit.confidence * hit.contextModifier;
    }

    let worstSeverity: Severity = Severity.INFO;
    for (const hit of fileHits) {
      if (SEVERITY_RANK[hit.severity] < SEVERITY_RANK[worstSeverity]) worstSeverity = hit.severity;
    }

    const lines = new Set<number>();
    for (const hit of fileHits) {
      if (hit.lineStart === null) continue;
      const end = hit.lineEnd ?? hit.lineStart;
      for (let line = hit.lineStart; line <= end && line - hit.lineStart < 500; line++) {
        lines.add(line);
      }
    }

    rows.push({
      path,
      families,
      ruleIds,
      hits: fileHits,
      risk: Math.round(risk * 100) / 100,
      worstSeverity,
      flaggedLines: lines.size,
    });
  }

  return rows.sort((a, b) => b.risk - a.risk || a.path.localeCompare(b.path));
}

// ---------------------------------------------------------------------------
// Typosquat neighbourhood
// ---------------------------------------------------------------------------

export interface SimilarCandidate {
  targetPackage: string;
  distance: number;
  technique: string;
  similarity: number;
  targetDownloads: number;
  /** Set when the org has also analysed the package being resembled. */
  analysedEcosystem: Ecosystem | null;
}

export interface Impersonator {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  distance: number;
  technique: string;
  verdict: Verdict | null;
  weeklyDownloads: number;
}

export interface SimilarPackages {
  ecosystem: Ecosystem;
  name: string;
  weeklyDownloads: number;
  /** Popular packages this one resembles — the reason it may be a typosquat. */
  candidates: SimilarCandidate[];
  /** Packages the org has analysed that resemble *this* one. */
  impersonators: Impersonator[];
}

export async function getSimilarPackages(
  ctx: AuthContext,
  ecosystem: Ecosystem,
  name: string,
): Promise<SimilarPackages> {
  assertCan(ctx, 'scan:read', { orgId: ctx.orgId });

  const pkg = await prisma.package.findUnique({
    where: { ecosystem_name: { ecosystem, name } },
    select: { weeklyDownloads: true },
  });
  if (!pkg) throw new NotFoundError('That package has not been analysed here yet.');

  const [outbound, inbound] = await Promise.all([
    prisma.typosquatMatch.findMany({
      where: {
        analysis: { orgId: ctx.orgId, packageVersion: { package: { ecosystem, name } } },
      },
      orderBy: [{ distance: 'asc' }, { targetDownloads: 'desc' }],
      take: 100,
    }),
    prisma.typosquatMatch.findMany({
      where: {
        targetPackage: name,
        analysis: {
          orgId: ctx.orgId,
          packageVersion: { package: { name: { not: name } } },
        },
      },
      orderBy: [{ distance: 'asc' }],
      take: 100,
      include: {
        analysis: {
          select: {
            verdict: true,
            packageVersion: {
              select: {
                version: true,
                package: { select: { name: true, ecosystem: true, weeklyDownloads: true } },
              },
            },
          },
        },
      },
    }),
  ]);

  const targets = [...new Set(outbound.map((match) => match.targetPackage))];
  const known = targets.length
    ? await prisma.package.findMany({
        where: { name: { in: targets } },
        select: { name: true, ecosystem: true },
      })
    : [];
  const knownByName = new Map(known.map((row) => [row.name, row.ecosystem]));

  const seen = new Set<string>();
  const candidates: SimilarCandidate[] = [];
  for (const match of outbound) {
    if (seen.has(match.targetPackage)) continue;
    seen.add(match.targetPackage);
    candidates.push({
      targetPackage: match.targetPackage,
      distance: match.distance,
      technique: match.technique,
      similarity: match.similarity,
      targetDownloads: match.targetDownloads,
      analysedEcosystem: knownByName.get(match.targetPackage) ?? null,
    });
  }

  const impersonatorSeen = new Set<string>();
  const impersonators: Impersonator[] = [];
  for (const match of inbound) {
    const source = match.analysis.packageVersion;
    const key = `${source.package.ecosystem}:${source.package.name}:${source.version}`;
    if (impersonatorSeen.has(key)) continue;
    impersonatorSeen.add(key);
    impersonators.push({
      ecosystem: source.package.ecosystem,
      name: source.package.name,
      version: source.version,
      distance: match.distance,
      technique: match.technique,
      verdict: asVerdict(match.analysis.verdict),
      weeklyDownloads: source.package.weeklyDownloads,
    });
  }

  return {
    ecosystem,
    name,
    weeklyDownloads: pkg.weeklyDownloads,
    candidates,
    impersonators,
  };
}

/** The version published immediately before `version`, when the org has analysed it. */
export async function previousAnalysedVersion(
  ctx: AuthContext,
  ecosystem: Ecosystem,
  name: string,
  version: string,
): Promise<string | null> {
  assertCan(ctx, 'scan:read', { orgId: ctx.orgId });

  const current = await prisma.packageVersion.findFirst({
    where: { version, package: { ecosystem, name } },
    select: { publishedAt: true },
  });

  const rows = await prisma.packageVersion.findMany({
    where: {
      package: { ecosystem, name },
      version: { not: version },
      analyses: {
        some: {
          orgId: ctx.orgId,
          status: { in: [AnalysisStatus.COMPLETED, AnalysisStatus.PARTIAL] },
        },
      },
      ...(current?.publishedAt ? { publishedAt: { lt: current.publishedAt } } : {}),
    },
    orderBy: [{ publishedAt: 'desc' }, { version: 'desc' }],
    take: 1,
    select: { version: true },
  });

  return rows[0]?.version ?? null;
}
