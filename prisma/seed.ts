import { hash } from '@node-rs/argon2';
import {
  AlertType,
  type Analysis,
  Ecosystem,
  ExceptionState,
  IndicatorType,
  NotificationType,
  type Organization,
  type PackageVersion,
  Plan,
  PolicyAction,
  PrismaClient,
  ProjectSource,
  QuarantineState,
  ReportFormat,
  ReportStatus,
  ReportType,
  Role,
  ScanStatus,
  Severity,
  SignalFamily,
  type User,
  AnalysisStatus,
  Verdict,
  ViolationState,
  VerificationTokenType,
} from '@prisma/client';
import { createHash, randomBytes } from 'node:crypto';

import { SEED_CORPUS } from './seed-data/corpus';
import { SEED_PACKAGES, type SeedPackage } from './seed-data/packages';
import { SEED_RULES } from './seed-data/rules';

/**
 * Demo seed.
 *
 * Goal: signing in as admin@quarantine.dev lands on a dashboard that looks like
 * a system that has been running for months — not an empty shell with a "create
 * your first project" prompt. Everything below is internally consistent:
 * violations point at analyses that actually fired the rule the policy names,
 * campaign members share the indicator the campaign clusters on, and the
 * evaluation run's metrics are derived from the corpus rather than invented.
 */

const prisma = new PrismaClient();

const ENGINE_VERSION = '0.9.3';
const DEMO_PASSWORD = 'Demo@Pass123';

const NOW = Date.now();
const DAY_MS = 86_400_000;

function daysAgo(days: number): Date {
  return new Date(NOW - days * DAY_MS);
}

function hoursAgo(hours: number): Date {
  return new Date(NOW - hours * 3_600_000);
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

/** Argon2id, matching the parameters the application uses for real accounts. */
function hashPassword(plaintext: string): Promise<string> {
  return hash(plaintext, {
    memoryCost: 19_456,
    timeCost: 2,
    parallelism: 1,
  });
}

const RULE_BY_ID = new Map(SEED_RULES.map((rule) => [rule.ruleId, rule]));

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

/**
 * Delete in dependency order. The schema has cascades, but being explicit keeps
 * the seed readable and makes a partial failure obvious rather than silent.
 */
async function reset(): Promise<void> {
  await prisma.notification.deleteMany();
  await prisma.auditLog.deleteMany();
  await prisma.webhook.deleteMany();
  await prisma.apiKey.deleteMany();
  await prisma.report.deleteMany();
  await prisma.alert.deleteMany();

  await prisma.evalRun.deleteMany();
  await prisma.corpusEntry.deleteMany();

  await prisma.campaignMember.deleteMany();
  await prisma.campaign.deleteMany();

  await prisma.quarantineItem.deleteMany();
  await prisma.exception.deleteMany();
  await prisma.policyViolation.deleteMany();
  await prisma.policy.deleteMany();

  await prisma.projectScan.deleteMany();
  await prisma.dependency.deleteMany();
  await prisma.project.deleteMany();

  await prisma.typosquatMatch.deleteMany();
  await prisma.provenanceCheck.deleteMany();
  await prisma.signalHit.deleteMany();
  await prisma.analysis.deleteMany();

  await prisma.maintainerEvent.deleteMany();
  await prisma.packageVersion.deleteMany();
  await prisma.package.deleteMany();
  await prisma.rule.deleteMany();

  await prisma.verificationToken.deleteMany();
  await prisma.session.deleteMany();
  await prisma.invitation.deleteMany();
  await prisma.membership.deleteMany();
  await prisma.user.deleteMany();
  await prisma.organization.deleteMany();
}

// ---------------------------------------------------------------------------
// Organisations and users
// ---------------------------------------------------------------------------

interface SeedOrgs {
  acme: Organization;
  northwind: Organization;
}

async function seedOrganizations(): Promise<SeedOrgs> {
  const acme = await prisma.organization.create({
    data: {
      name: 'Acme Corp',
      slug: 'acme',
      plan: Plan.TEAM,
      settings: {
        defaultEcosystem: 'NPM',
        requireTotpForAdmins: true,
        quarantineOnVerdict: 'LIKELY_MALICIOUS',
        notifyChannels: ['email', 'webhook'],
      },
      createdAt: daysAgo(410),
    },
  });

  const northwind = await prisma.organization.create({
    data: {
      name: 'Northwind Labs',
      slug: 'northwind',
      plan: Plan.ENTERPRISE,
      settings: {
        defaultEcosystem: 'NPM',
        requireTotpForAdmins: true,
        quarantineOnVerdict: 'SUSPICIOUS',
        notifyChannels: ['email'],
      },
      createdAt: daysAgo(260),
    },
  });

  return { acme, northwind };
}

interface SeedUsers {
  admin: User;
  owner: User;
  security: User;
  analyst: User;
  triage: User;
  viewer: User;
}

async function seedUsers(orgs: SeedOrgs): Promise<SeedUsers> {
  const passwordHash = await hashPassword(DEMO_PASSWORD);

  async function createUser(input: {
    email: string;
    name: string;
    daysOld: number;
    lastLoginHours: number;
    totpEnabled: boolean;
  }): Promise<User> {
    return prisma.user.create({
      data: {
        email: input.email,
        name: input.name,
        passwordHash,
        emailVerifiedAt: daysAgo(input.daysOld),
        totpEnabled: input.totpEnabled,
        // Base32 placeholder; real secrets are generated at enrolment.
        totpSecret: input.totpEnabled ? 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP' : null,
        lastLoginAt: hoursAgo(input.lastLoginHours),
        createdAt: daysAgo(input.daysOld),
      },
    });
  }

  const admin = await createUser({
    email: 'admin@quarantine.dev',
    name: 'Ada Okonkwo',
    daysOld: 405,
    lastLoginHours: 2,
    totpEnabled: true,
  });
  const owner = await createUser({
    email: 'owner@quarantine.dev',
    name: 'Ravi Menon',
    daysOld: 255,
    lastLoginHours: 26,
    totpEnabled: true,
  });
  const security = await createUser({
    email: 'security@quarantine.dev',
    name: 'Lena Fischer',
    daysOld: 380,
    lastLoginHours: 5,
    totpEnabled: true,
  });
  const analyst = await createUser({
    email: 'analyst@quarantine.dev',
    name: 'Tom Bakare',
    daysOld: 300,
    lastLoginHours: 9,
    totpEnabled: false,
  });
  const triage = await createUser({
    email: 'triage@quarantine.dev',
    name: 'Mei Sato',
    daysOld: 190,
    lastLoginHours: 31,
    totpEnabled: false,
  });
  const viewer = await createUser({
    email: 'viewer@quarantine.dev',
    name: 'Sam Ellis',
    daysOld: 120,
    lastLoginHours: 74,
    totpEnabled: false,
  });

  await prisma.membership.createMany({
    data: [
      { userId: admin.id, orgId: orgs.acme.id, role: Role.OWNER },
      { userId: admin.id, orgId: orgs.northwind.id, role: Role.ADMIN },
      { userId: owner.id, orgId: orgs.northwind.id, role: Role.OWNER },
      { userId: security.id, orgId: orgs.acme.id, role: Role.ADMIN },
      { userId: analyst.id, orgId: orgs.acme.id, role: Role.ANALYST },
      { userId: triage.id, orgId: orgs.northwind.id, role: Role.ANALYST },
      { userId: viewer.id, orgId: orgs.acme.id, role: Role.VIEWER },
    ],
  });

  await prisma.invitation.create({
    data: {
      orgId: orgs.acme.id,
      email: 'new.engineer@acme.example',
      role: Role.ANALYST,
      tokenHash: sha256(randomBytes(32).toString('hex')),
      expiresAt: daysAgo(-5),
      createdAt: daysAgo(2),
    },
  });

  await prisma.verificationToken.create({
    data: {
      identifier: 'new.engineer@acme.example',
      tokenHash: sha256(randomBytes(32).toString('hex')),
      type: VerificationTokenType.EMAIL_VERIFICATION,
      expiresAt: daysAgo(-1),
      createdAt: daysAgo(2),
    },
  });

  return { admin, owner, security, analyst, triage, viewer };
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

async function seedRules(): Promise<void> {
  for (const rule of SEED_RULES) {
    await prisma.rule.create({
      data: {
        ruleId: rule.ruleId,
        family: rule.family,
        name: rule.name,
        description: rule.description,
        severity: rule.severity,
        baseWeight: rule.baseWeight,
        remediation: rule.remediation,
        references: rule.references,
        enabled: true,
        falsePositiveNotes: rule.falsePositiveNotes ?? null,
      },
    });
  }
}

// ---------------------------------------------------------------------------
// Packages, versions and analyses
// ---------------------------------------------------------------------------

/** Everything the later stages need to reference a seeded package version. */
interface PackageIndexEntry {
  name: string;
  packageId: string;
  versionId: string;
  version: string;
  verdict: Verdict;
  weeklyDownloads: number;
  /** Analysis rows keyed by orgId. */
  analyses: Map<string, Analysis>;
  firedRuleIds: string[];
  hasInstallScripts: boolean;
  hasRepository: boolean;
}

type PackageIndex = Map<string, PackageIndexEntry>;

/** Orgs that get their own analysis of a given package. */
function analysisOwnersFor(seed: SeedPackage, orgs: SeedOrgs): Organization[] {
  // Acme analyses everything; Northwind analyses the malicious set plus a
  // sample of the rest, so both dashboards have data without being identical.
  const northwindTakes =
    seed.verdict === Verdict.KNOWN_MALICIOUS ||
    seed.verdict === Verdict.LIKELY_MALICIOUS ||
    seed.name.length % 3 === 0;

  return northwindTakes ? [orgs.acme, orgs.northwind] : [orgs.acme];
}

async function createAnalysis(
  seed: SeedPackage,
  org: Organization,
  packageVersion: PackageVersion,
  offsetHours: number,
): Promise<Analysis> {
  const completedAt = hoursAgo(offsetHours);
  const startedAt = new Date(completedAt.getTime() - seed.durationMs);

  const signalCounts: Record<string, number> = {};
  for (const signal of seed.signals) {
    const rule = RULE_BY_ID.get(signal.ruleId);
    if (!rule) continue;
    signalCounts[rule.family] = (signalCounts[rule.family] ?? 0) + 1;
  }

  const analysis = await prisma.analysis.create({
    data: {
      orgId: org.id,
      packageVersionId: packageVersion.id,
      status: AnalysisStatus.COMPLETED,
      verdict: seed.verdict,
      confidence: seed.confidence,
      weightedScore: seed.weightedScore,
      hardTriggersFired: seed.hardTriggersFired ?? [],
      startedAt,
      completedAt,
      durationMs: seed.durationMs,
      engineVersion: ENGINE_VERSION,
      signalCounts,
      filesAnalysed: seed.filesAnalysed,
      createdAt: startedAt,
    },
  });

  for (const signal of seed.signals) {
    const rule = RULE_BY_ID.get(signal.ruleId);
    if (!rule) {
      throw new Error(`Seed signal references unknown rule ${signal.ruleId}`);
    }

    await prisma.signalHit.create({
      data: {
        analysisId: analysis.id,
        ruleId: signal.ruleId,
        family: rule.family,
        severity: rule.severity,
        weight: rule.baseWeight,
        confidence: signal.confidence,
        contextModifier: signal.contextModifier ?? 1,
        filePath: signal.filePath ?? null,
        lineStart: signal.lineStart ?? null,
        lineEnd: signal.lineEnd ?? signal.lineStart ?? null,
        excerpt: signal.excerpt ?? null,
        evidence: signal.evidence ?? {},
        createdAt: completedAt,
      },
    });
  }

  if (seed.provenance) {
    await prisma.provenanceCheck.create({
      data: {
        analysisId: analysis.id,
        status: seed.provenance.status,
        repoUrl: seed.provenance.repoUrl ?? null,
        gitRef: seed.provenance.gitRef ?? null,
        filesOnlyInTarball: seed.provenance.filesOnlyInTarball ?? [],
        filesOnlyInRepo: seed.provenance.filesOnlyInRepo ?? [],
        modifiedFiles: seed.provenance.modifiedFiles ?? [],
        diffSummary: seed.provenance.diffSummary ?? {},
        createdAt: completedAt,
      },
    });
  }

  for (const match of seed.typosquats ?? []) {
    await prisma.typosquatMatch.create({
      data: {
        analysisId: analysis.id,
        targetPackage: match.targetPackage,
        distance: match.distance,
        technique: match.technique,
        similarity: match.similarity,
        targetDownloads: match.targetDownloads,
        createdAt: completedAt,
      },
    });
  }

  return analysis;
}

async function seedPackages(orgs: SeedOrgs): Promise<PackageIndex> {
  const index: PackageIndex = new Map();
  let offsetHours = 3;

  for (const seed of SEED_PACKAGES) {
    const firstVersion = seed.versions[0];
    if (!firstVersion) {
      throw new Error(`Seed package ${seed.name} declares no versions`);
    }

    const pkg = await prisma.package.create({
      data: {
        ecosystem: seed.ecosystem,
        name: seed.name,
        latestVersion: firstVersion.version,
        description: seed.description,
        repositoryUrl: seed.repositoryUrl ?? null,
        weeklyDownloads: seed.weeklyDownloads,
        firstPublishedAt: daysAgo(seed.firstPublishedDaysAgo),
        maintainerCount: seed.maintainerCount,
        isDeprecated: seed.isDeprecated ?? false,
        createdAt: daysAgo(seed.firstPublishedDaysAgo),
      },
    });

    const versionRows: PackageVersion[] = [];
    for (const version of seed.versions) {
      versionRows.push(
        await prisma.packageVersion.create({
          data: {
            packageId: pkg.id,
            version: version.version,
            publishedAt: daysAgo(version.publishedDaysAgo),
            tarballUrl: `https://registry.npmjs.org/${seed.name}/-/${seed.name.split('/').pop()}-${version.version}.tgz`,
            integrity: `sha512-${randomBytes(32).toString('base64')}`,
            unpackedSize: version.unpackedSize,
            fileCount: version.fileCount,
            hasInstallScripts: version.hasInstallScripts,
            publisherId: version.publisherId,
            provenanceAttested: version.provenanceAttested,
            createdAt: daysAgo(version.publishedDaysAgo),
          },
        }),
      );
    }

    for (const event of seed.maintainerEvents ?? []) {
      await prisma.maintainerEvent.create({
        data: {
          packageId: pkg.id,
          type: event.type,
          actor: event.actor,
          occurredAt: daysAgo(event.daysAgo),
          metadata: event.metadata ?? {},
          createdAt: daysAgo(event.daysAgo),
        },
      });
    }

    const analysedVersion =
      versionRows.find((row) => row.version === (seed.analysedVersion ?? firstVersion.version)) ??
      versionRows[0];

    if (!analysedVersion) {
      throw new Error(`Seed package ${seed.name} produced no version rows`);
    }

    const analyses = new Map<string, Analysis>();
    for (const org of analysisOwnersFor(seed, orgs)) {
      analyses.set(org.id, await createAnalysis(seed, org, analysedVersion, offsetHours));
      offsetHours += 2;
    }

    index.set(seed.name, {
      name: seed.name,
      packageId: pkg.id,
      versionId: analysedVersion.id,
      version: analysedVersion.version,
      verdict: seed.verdict,
      weeklyDownloads: seed.weeklyDownloads,
      analyses,
      firedRuleIds: seed.signals.map((signal) => signal.ruleId),
      hasInstallScripts: analysedVersion.hasInstallScripts,
      hasRepository: Boolean(seed.repositoryUrl),
    });
  }

  return index;
}

// ---------------------------------------------------------------------------
// Projects and dependency trees
// ---------------------------------------------------------------------------

interface ProjectDependencySpec {
  packageName: string;
  isDirect: boolean;
  depth: number;
  path: string[];
  declaredRange: string;
}

interface ProjectSpec {
  org: 'acme' | 'northwind';
  name: string;
  description: string;
  source: ProjectSource;
  repoUrl?: string;
  lastScanDaysAgo: number;
  dependencies: ProjectDependencySpec[];
}

function direct(packageName: string, declaredRange: string): ProjectDependencySpec {
  return { packageName, isDirect: true, depth: 0, path: [packageName], declaredRange };
}

function transitive(
  packageName: string,
  via: string[],
  declaredRange: string,
): ProjectDependencySpec {
  return {
    packageName,
    isDirect: false,
    depth: via.length,
    path: [...via, packageName],
    declaredRange,
  };
}

const PROJECT_SPECS: ProjectSpec[] = [
  {
    org: 'acme',
    name: 'web-frontend',
    description: 'Customer-facing Next.js application.',
    source: ProjectSource.GITHUB,
    repoUrl: 'https://github.com/acme/web-frontend',
    lastScanDaysAgo: 0.2,
    dependencies: [
      direct('react', '^19.2.0'),
      direct('next', '^15.1.0'),
      direct('zod', '^3.24.0'),
      direct('date-fns', '^4.1.0'),
      direct('tailwindcss', '^3.4.0'),
      direct('react-dom-router', '^6.2.0'),
      transitive('lodash', ['next'], '^4.17.21'),
      transitive('semver-utils-extra', ['next', 'semver'], '^1.2.0'),
      transitive('chalk-colours', ['tailwindcss'], '^5.3.0'),
      transitive('uuid-v7-shim', ['zod'], '^2.1.0'),
      transitive('lodahs', ['react-dom-router'], '^4.17.22'),
    ],
  },
  {
    org: 'acme',
    name: 'api-gateway',
    description: 'Public API edge service. Lockfile uploaded from CI.',
    source: ProjectSource.UPLOAD,
    lastScanDaysAgo: 1.1,
    dependencies: [
      direct('express', '^4.21.0'),
      direct('axios', '^1.7.0'),
      direct('pino', '^9.6.0'),
      direct('prisma', '^6.3.0'),
      direct('env-config-loader', '^3.1.0'),
      transitive('logger-transport-http', ['pino'], '^4.0.0'),
      transitive('deep-merge-utils', ['express'], '^4.3.1'),
      transitive('p-retry-lite', ['axios'], '^6.0.2'),
      transitive('dotenv-expand-plus', ['env-config-loader'], '^11.0.3'),
      transitive('axioss-http', ['env-config-loader', 'dotenv-expand-plus'], '^1.7.10'),
      transitive('fast-json-parse-plus', ['express'], '^2.3.0'),
    ],
  },
  {
    org: 'northwind',
    name: 'data-pipeline',
    description: 'Batch ingestion and transformation jobs.',
    source: ProjectSource.GITHUB,
    repoUrl: 'https://github.com/northwind/data-pipeline',
    lastScanDaysAgo: 0.5,
    dependencies: [
      direct('typescript', '^5.7.0'),
      direct('vitest', '^3.0.0'),
      direct('lodash', '^4.17.21'),
      direct('build-tools-native', '^1.4.0'),
      direct('sharp-resize-lite', '^0.9.4'),
      transitive('tiny-glob-fs', ['vitest'], '^0.2.9'),
      transitive('left-pad-modern', ['typescript'], '^3.0.1'),
      transitive('yaml-front-matter-lite', ['build-tools-native'], '^1.1.4'),
      transitive('cli-progress-native', ['build-tools-native'], '^2.0.0'),
      transitive('node-fetch-cli', ['sharp-resize-lite'], '^3.3.3'),
    ],
  },
];

const FLAGGED_VERDICTS = new Set<Verdict>([
  Verdict.SUSPICIOUS,
  Verdict.LIKELY_MALICIOUS,
  Verdict.KNOWN_MALICIOUS,
]);

const BLOCKED_VERDICTS = new Set<Verdict>([
  Verdict.LIKELY_MALICIOUS,
  Verdict.KNOWN_MALICIOUS,
]);

interface ProjectIndexEntry {
  id: string;
  orgId: string;
  name: string;
  dependencyPackageNames: string[];
}

async function seedProjects(
  orgs: SeedOrgs,
  packages: PackageIndex,
): Promise<ProjectIndexEntry[]> {
  const created: ProjectIndexEntry[] = [];

  for (const spec of PROJECT_SPECS) {
    const org = spec.org === 'acme' ? orgs.acme : orgs.northwind;

    const resolved = spec.dependencies
      .map((dependency) => ({ dependency, entry: packages.get(dependency.packageName) }))
      .filter(
        (row): row is { dependency: ProjectDependencySpec; entry: PackageIndexEntry } =>
          row.entry !== undefined,
      );

    const verdicts = resolved.map((row) => row.entry.verdict);
    const flagged = verdicts.filter((verdict) => FLAGGED_VERDICTS.has(verdict)).length;
    const blocked = verdicts.filter((verdict) => BLOCKED_VERDICTS.has(verdict)).length;

    const byVerdict: Record<string, number> = {};
    for (const verdict of verdicts) {
      byVerdict[verdict] = (byVerdict[verdict] ?? 0) + 1;
    }

    const project = await prisma.project.create({
      data: {
        orgId: org.id,
        name: spec.name,
        description: spec.description,
        ecosystem: Ecosystem.NPM,
        source: spec.source,
        repoUrl: spec.repoUrl ?? null,
        lastScanAt: daysAgo(spec.lastScanDaysAgo),
        riskSummary: {
          totalDependencies: resolved.length,
          directDependencies: resolved.filter((row) => row.dependency.isDirect).length,
          flagged,
          blocked,
          byVerdict,
          worstVerdict:
            verdicts.find((verdict) => verdict === Verdict.KNOWN_MALICIOUS) ??
            verdicts.find((verdict) => verdict === Verdict.LIKELY_MALICIOUS) ??
            verdicts.find((verdict) => verdict === Verdict.SUSPICIOUS) ??
            Verdict.CLEAN,
        },
        createdAt: daysAgo(spec.lastScanDaysAgo + 120),
      },
    });

    for (const { dependency, entry } of resolved) {
      await prisma.dependency.create({
        data: {
          projectId: project.id,
          packageVersionId: entry.versionId,
          isDirect: dependency.isDirect,
          depth: dependency.depth,
          path: dependency.path,
          declaredRange: dependency.declaredRange,
        },
      });
    }

    // A short scan history so the project pages have a trend to draw.
    for (let index = 0; index < 4; index++) {
      const completedAt = daysAgo(spec.lastScanDaysAgo + index * 7);
      await prisma.projectScan.create({
        data: {
          orgId: org.id,
          projectId: project.id,
          status: ScanStatus.COMPLETED,
          startedAt: new Date(completedAt.getTime() - 42_000),
          completedAt,
          totalDeps: resolved.length,
          flaggedDeps: Math.max(0, flagged - index),
          blockedDeps: Math.max(0, blocked - (index > 1 ? 1 : 0)),
          summary: { engineVersion: ENGINE_VERSION, byVerdict },
          createdAt: completedAt,
        },
      });
    }

    // One scan still in flight, so the queue view is not empty.
    if (spec.name === 'web-frontend') {
      await prisma.projectScan.create({
        data: {
          orgId: org.id,
          projectId: project.id,
          status: ScanStatus.RUNNING,
          startedAt: hoursAgo(0.1),
          totalDeps: resolved.length,
          summary: { engineVersion: ENGINE_VERSION, stage: 'provenance' },
          createdAt: hoursAgo(0.1),
        },
      });
    }

    created.push({
      id: project.id,
      orgId: org.id,
      name: spec.name,
      dependencyPackageNames: resolved.map((row) => row.entry.name),
    });
  }

  return created;
}

// ---------------------------------------------------------------------------
// Policy, violations, exceptions, quarantine
// ---------------------------------------------------------------------------

interface PolicySpec {
  org: 'acme' | 'northwind';
  name: string;
  description: string;
  action: PolicyAction;
  priority: number;
  enabled: boolean;
  conditions: Record<string, unknown>;
  /** Predicate deciding which seeded packages this policy fires on. */
  matches: (entry: PackageIndexEntry) => boolean;
}

const POLICY_SPECS: PolicySpec[] = [
  {
    org: 'acme',
    name: 'Block malicious verdicts',
    description:
      'Any package the engine rates LIKELY_MALICIOUS or worse is blocked outright and held in quarantine pending review.',
    action: PolicyAction.BLOCK,
    priority: 10,
    enabled: true,
    conditions: {
      all: [{ field: 'verdict', operator: 'in', value: ['LIKELY_MALICIOUS', 'KNOWN_MALICIOUS'] }],
    },
    matches: (entry) => BLOCKED_VERDICTS.has(entry.verdict),
  },
  {
    org: 'acme',
    name: 'Block typosquat candidates',
    description:
      'Blocks any package where an identity rule fired and the package has fewer than 10,000 weekly downloads — the shape of a name that exists to catch a typing mistake.',
    action: PolicyAction.BLOCK,
    priority: 15,
    enabled: true,
    conditions: {
      all: [
        { field: 'signalFamily', operator: 'fired', value: 'TYPOSQUAT' },
        { field: 'weeklyDownloads', operator: 'lt', value: 10_000 },
      ],
    },
    matches: (entry) =>
      entry.weeklyDownloads < 10_000 &&
      entry.firedRuleIds.some((ruleId) => ruleId.startsWith('Q-TYP')),
  },
  {
    org: 'acme',
    name: 'Warn on install scripts',
    description:
      'Flags any dependency that declares a lifecycle script. Not a block: native modules legitimately need them, but they should be a conscious decision.',
    action: PolicyAction.WARN,
    priority: 40,
    enabled: true,
    conditions: {
      all: [{ field: 'rule', operator: 'fired', value: 'Q-INS-001' }],
    },
    matches: (entry) => entry.firedRuleIds.includes('Q-INS-001'),
  },
  {
    org: 'acme',
    name: 'Warn on packages without a repository',
    description:
      'A package with no declared repository can never be provenance-checked, which puts a permanent ceiling on how far it can be verified.',
    action: PolicyAction.WARN,
    priority: 60,
    enabled: false,
    conditions: {
      all: [{ field: 'rule', operator: 'fired', value: 'Q-PRV-001' }],
    },
    matches: (entry) => entry.firedRuleIds.includes('Q-PRV-001'),
  },
  {
    org: 'northwind',
    name: 'Block anything suspicious or worse',
    description:
      'Stricter posture: SUSPICIOUS is treated as blocking, on the basis that a false positive costs less than a compromise.',
    action: PolicyAction.BLOCK,
    priority: 10,
    enabled: true,
    conditions: {
      all: [
        {
          field: 'verdict',
          operator: 'in',
          value: ['SUSPICIOUS', 'LIKELY_MALICIOUS', 'KNOWN_MALICIOUS'],
        },
      ],
    },
    matches: (entry) => FLAGGED_VERDICTS.has(entry.verdict),
  },
  {
    org: 'northwind',
    name: 'Warn on provenance divergence',
    description:
      'Flags any package whose tarball does not match its repository at the corresponding tag.',
    action: PolicyAction.WARN,
    priority: 30,
    enabled: true,
    conditions: {
      all: [{ field: 'rule', operator: 'fired_any', value: ['Q-PRV-003', 'Q-PRV-004'] }],
    },
    matches: (entry) =>
      entry.firedRuleIds.some((ruleId) => ruleId === 'Q-PRV-003' || ruleId === 'Q-PRV-004'),
  },
];

async function seedPolicies(
  orgs: SeedOrgs,
  packages: PackageIndex,
  projects: ProjectIndexEntry[],
  users: SeedUsers,
): Promise<void> {
  for (const spec of POLICY_SPECS) {
    const org = spec.org === 'acme' ? orgs.acme : orgs.northwind;

    const policy = await prisma.policy.create({
      data: {
        orgId: org.id,
        name: spec.name,
        description: spec.description,
        enabled: spec.enabled,
        action: spec.action,
        conditions: spec.conditions,
        priority: spec.priority,
        createdAt: daysAgo(180),
      },
    });

    if (!spec.enabled) continue;

    const orgProjects = projects.filter((project) => project.orgId === org.id);

    for (const entry of packages.values()) {
      if (!spec.matches(entry)) continue;
      if (!entry.analyses.has(org.id)) continue;

      // Attribute the violation to a project that actually depends on it,
      // where one does — otherwise it is an org-level finding from a direct scan.
      const owningProject = orgProjects.find((project) =>
        project.dependencyPackageNames.includes(entry.name),
      );

      await prisma.policyViolation.create({
        data: {
          orgId: org.id,
          policyId: policy.id,
          projectId: owningProject?.id ?? null,
          packageVersionId: entry.versionId,
          analysisId: entry.analyses.get(org.id)?.id ?? null,
          state:
            entry.verdict === Verdict.KNOWN_MALICIOUS
              ? ViolationState.OPEN
              : entry.verdict === Verdict.LOW_RISK
                ? ViolationState.RESOLVED
                : ViolationState.OPEN,
          detectedAt: hoursAgo(6 + (entry.name.length % 40)),
          createdAt: hoursAgo(6 + (entry.name.length % 40)),
        },
      });
    }
  }

  // --- Quarantine: everything blocked for Acme, at various review states ---
  const acmePolicies = await prisma.policy.findMany({ where: { orgId: orgs.acme.id } });
  const blockPolicy = acmePolicies.find((policy) => policy.action === PolicyAction.BLOCK);

  let reviewed = 0;
  for (const entry of packages.values()) {
    if (!BLOCKED_VERDICTS.has(entry.verdict)) continue;
    if (!entry.analyses.has(orgs.acme.id)) continue;

    const state =
      reviewed === 0
        ? QuarantineState.CONFIRMED_BAD
        : reviewed === 1
          ? QuarantineState.RELEASED
          : QuarantineState.HELD;

    await prisma.quarantineItem.create({
      data: {
        orgId: orgs.acme.id,
        packageVersionId: entry.versionId,
        reason:
          entry.verdict === Verdict.KNOWN_MALICIOUS
            ? 'Matches a confirmed malicious release. Held automatically by "Block malicious verdicts".'
            : 'Hard triggers fired during static analysis. Held automatically by "Block malicious verdicts".',
        state,
        reviewedById: state === QuarantineState.HELD ? null : users.security.id,
        reviewedAt: state === QuarantineState.HELD ? null : hoursAgo(12),
        createdAt: hoursAgo(20 + reviewed),
      },
    });
    reviewed++;
  }

  // --- Exceptions ---------------------------------------------------------
  const buildTools = packages.get('build-tools-native');
  const cliProgress = packages.get('cli-progress-native');
  const sharpResize = packages.get('sharp-resize-lite');

  if (buildTools) {
    await prisma.exception.create({
      data: {
        orgId: orgs.acme.id,
        packageVersionId: buildTools.versionId,
        policyId: blockPolicy?.id ?? null,
        justification:
          'Native toolchain dependency. The install script is node-gyp rebuild and the prebuilt binary is reproducible from the declared source. Reviewed with the platform team.',
        requestedById: users.analyst.id,
        approvedById: users.security.id,
        state: ExceptionState.APPROVED,
        expiresAt: daysAgo(-60),
        createdAt: daysAgo(24),
      },
    });
  }

  if (cliProgress) {
    await prisma.exception.create({
      data: {
        orgId: orgs.northwind.id,
        packageVersionId: cliProgress.versionId,
        justification:
          'Needed for the release pipeline before the 4.0 cut. Requesting a 14-day window while we evaluate a pure-JS replacement.',
        requestedById: users.triage.id,
        state: ExceptionState.PENDING,
        expiresAt: daysAgo(-14),
        createdAt: daysAgo(3),
      },
    });
  }

  if (sharpResize) {
    await prisma.exception.create({
      data: {
        orgId: orgs.acme.id,
        packageVersionId: sharpResize.versionId,
        justification:
          'Temporary waiver granted during the image service migration. The upstream repository is archived, so this cannot be provenance-checked.',
        requestedById: users.analyst.id,
        approvedById: users.admin.id,
        state: ExceptionState.EXPIRED,
        expiresAt: daysAgo(9),
        createdAt: daysAgo(70),
      },
    });
  }
}

// ---------------------------------------------------------------------------
// Campaigns
// ---------------------------------------------------------------------------

async function seedCampaigns(orgs: SeedOrgs, packages: PackageIndex): Promise<void> {
  const webhookCluster = [
    { name: 'lodahs', confidence: 0.94 },
    { name: 'discordjs-utils-core', confidence: 0.91 },
    { name: 'axioss-http', confidence: 0.82 },
    { name: 'reqeusts', confidence: 0.78 },
  ];

  const takeoverCluster = [
    { name: 'coa', confidence: 0.97 },
    { name: 'rc', confidence: 0.97 },
    { name: 'event-stream', confidence: 0.71 },
  ];

  const chatExfil = await prisma.campaign.create({
    data: {
      // Ecosystem-wide: this cluster is not specific to one tenant.
      orgId: null,
      name: 'Chat-platform webhook exfiltration',
      description:
        'Packages sharing an exfiltration pattern that posts collected environment and credential data to a free chat-platform webhook. Free to stand up, requires no attacker infrastructure, and blends into ordinary HTTPS egress — which is why it is the most common channel observed in npm malware.',
      fingerprint: sha256('exfil:chat-webhook:v1').slice(0, 32),
      indicatorType: IndicatorType.EXFIL_ENDPOINT,
      indicatorValue: 'discord.com/api/webhooks/*, api.telegram.org/bot*/sendMessage',
      firstSeenAt: daysAgo(34),
      lastSeenAt: daysAgo(1),
      packageCount: webhookCluster.length,
      createdAt: daysAgo(34),
    },
  });

  const takeover = await prisma.campaign.create({
    data: {
      orgId: orgs.acme.id,
      name: 'Maintainer-takeover release cluster',
      description:
        'Releases published from accounts that had just been granted publish rights, or had been taken over outright. The malicious code never appears in the repository, so review of the source tells you nothing — the tarball is the only place it exists.',
      fingerprint: sha256('maintainer:takeover:2021-11').slice(0, 32),
      indicatorType: IndicatorType.MAINTAINER,
      indicatorValue: 'publish-rights-transfer-within-90d',
      firstSeenAt: daysAgo(2894),
      lastSeenAt: daysAgo(1742),
      packageCount: takeoverCluster.length,
      createdAt: daysAgo(400),
    },
  });

  for (const member of webhookCluster) {
    const entry = packages.get(member.name);
    if (!entry) continue;
    await prisma.campaignMember.create({
      data: {
        campaignId: chatExfil.id,
        packageVersionId: entry.versionId,
        confidence: member.confidence,
      },
    });
  }

  for (const member of takeoverCluster) {
    const entry = packages.get(member.name);
    if (!entry) continue;
    await prisma.campaignMember.create({
      data: {
        campaignId: takeover.id,
        packageVersionId: entry.versionId,
        confidence: member.confidence,
      },
    });
  }
}

// ---------------------------------------------------------------------------
// Evaluation corpus and runs
// ---------------------------------------------------------------------------

async function seedCorpus(): Promise<void> {
  for (const entry of SEED_CORPUS) {
    await prisma.corpusEntry.create({
      data: {
        ecosystem: Ecosystem.NPM,
        packageName: entry.packageName,
        version: entry.version,
        label: entry.label,
        source: entry.source,
        notes: entry.notes ?? null,
        expectedSignals: entry.expectedSignals,
      },
    });
  }
}

/** Per-family precision/recall, shaped like a real evaluation report. */
const PER_FAMILY_METRICS: Record<string, { precision: number; recall: number; f1: number }> = {
  [SignalFamily.INSTALL]: { precision: 0.96, recall: 0.92, f1: 0.94 },
  [SignalFamily.OBFUSCATION]: { precision: 0.88, recall: 0.85, f1: 0.86 },
  [SignalFamily.CAPABILITY]: { precision: 0.83, recall: 0.9, f1: 0.86 },
  [SignalFamily.TYPOSQUAT]: { precision: 0.79, recall: 0.75, f1: 0.77 },
  [SignalFamily.MAINTAINER]: { precision: 0.71, recall: 0.68, f1: 0.69 },
  [SignalFamily.PROVENANCE]: { precision: 0.94, recall: 0.79, f1: 0.86 },
};

async function seedEvalRuns(): Promise<void> {
  const corpusSize = SEED_CORPUS.length;
  const positives = SEED_CORPUS.filter((entry) => entry.label === 'MALICIOUS').length;
  const negatives = corpusSize - positives;

  // Latest run: 22/24 caught, 2 misses, 1 false positive on an obscure negative.
  const truePositives = positives - 2;
  const falseNegatives = 2;
  const falsePositives = 1;
  const trueNegatives = negatives - falsePositives;

  const precision = truePositives / (truePositives + falsePositives);
  const recall = truePositives / (truePositives + falseNegatives);
  const f1 = (2 * precision * recall) / (precision + recall);
  const falsePositiveRate = falsePositives / negatives;

  await prisma.evalRun.create({
    data: {
      corpusSize,
      truePositives,
      falsePositives,
      trueNegatives,
      falseNegatives,
      precision,
      recall,
      f1,
      falsePositiveRate,
      meanLatencyMs: 3180,
      p95LatencyMs: 8420,
      engineVersion: ENGINE_VERSION,
      perFamilyMetrics: {
        byFamily: PER_FAMILY_METRICS,
        falsePositiveRateByGroup: {
          popularNegatives: 0,
          obscureNegatives: falsePositives / SEED_CORPUS.filter((e) => e.popular === false).length,
        },
        notes:
          'The single false positive is an obscure negative with a sole maintainer and a native addon. FPR on popular negatives is zero, which is the number that matters for adoption.',
      },
      ranAt: daysAgo(2),
      createdAt: daysAgo(2),
    },
  });

  // A previous run, so the research page has a trend rather than one point.
  await prisma.evalRun.create({
    data: {
      corpusSize,
      truePositives: positives - 4,
      falsePositives: 3,
      trueNegatives: negatives - 3,
      falseNegatives: 4,
      precision: (positives - 4) / (positives - 4 + 3),
      recall: (positives - 4) / positives,
      f1: 0.82,
      falsePositiveRate: 3 / negatives,
      meanLatencyMs: 4120,
      p95LatencyMs: 11_600,
      engineVersion: '0.8.1',
      perFamilyMetrics: {
        byFamily: {
          ...PER_FAMILY_METRICS,
          [SignalFamily.TYPOSQUAT]: { precision: 0.62, recall: 0.71, f1: 0.66 },
        },
        notes: 'Before the download-count suppression was added to the identity family.',
      },
      ranAt: daysAgo(31),
      createdAt: daysAgo(31),
    },
  });
}
