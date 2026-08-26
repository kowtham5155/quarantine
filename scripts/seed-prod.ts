/**
 * Production seed — the rule catalogue, and nothing else.
 *
 *     npx tsx scripts/seed-prod.ts
 *
 * ## Why this is not `prisma/seed.ts`
 *
 * The development seed calls `reset()`, which truncates every table. Pointing
 * that at a deployed database would delete the org using it. This script never
 * deletes anything and never overwrites an operator's decisions.
 *
 * ## Why the catalogue has to be seeded at all
 *
 * A `Rule` row carries the weight and severity the scorer multiplies a signal
 * by. With an empty catalogue the engine still runs and still fires signals,
 * but every hit is unattributed and every verdict is wrong in the direction
 * that matters: nothing scores. The catalogue is not demo data — it is part of
 * the engine that happens to live in Postgres.
 *
 * ## Idempotence
 *
 * Rules are upserted by `ruleId`. Catalogue *content* — name, description,
 * severity, weight, remediation, references — is refreshed on every run, so a
 * deploy carrying a reworded rule updates it. Two columns are deliberately left
 * alone once the row exists:
 *
 *   - `enabled`, because an operator may have switched a noisy rule off and a
 *     deploy must not switch it back on behind their back.
 *   - `falsePositiveNotes`, because those are written by whoever triaged the
 *     false positive, not by this file.
 *
 * Safe to run on every deploy, and safe to run twice.
 *
 * ## The optional demo account
 *
 * Set `SEED_DEMO_ACCOUNT=true` and `DEMO_PASSWORD=...` to create a read-only
 * account for a specific deployment, with a few real analyses behind it so the
 * dashboard is not empty.
 *
 * No password is written down in this repository, and there is no default. A
 * credential published for one demo instance, holding the VIEWER role, is a
 * different object from a guessable default shipped to everyone who clones the
 * project — the second is a vulnerability in every deployment at once. The
 * password is read from the environment, checked against the same policy the
 * registration form enforces, and refused if it is weak.
 */
import { Ecosystem, PrismaClient, Role } from '@prisma/client';

import { SEED_RULES } from '../prisma/seed-data/rules';
import { checkPasswordPolicy, hashPassword } from '../lib/password';
import * as analysisService from '../lib/services/analysis.service';

const prisma = new PrismaClient();

const DEMO_ORG_SLUG = 'quarantine-demo';
const DEMO_ORG_NAME = 'Quarantine Demo';
const DEMO_EMAIL = process.env.DEMO_EMAIL ?? 'demo@quarantine.dev';
/** Display name shown in the top bar and on audit entries. */
const DEMO_NAME = process.env.DEMO_NAME ?? 'Demo Viewer';

/**
 * What the demo dashboard is populated with.
 *
 * These are analysed for real, through the same engine the scan page uses:
 * the published tarball is downloaded, extracted under the bounded extractor
 * and read statically. Nothing here is a fabricated verdict — seeding a
 * pre-baked report would mean the first thing a visitor sees is the one part of
 * the product that was never run.
 *
 * A spread of shapes on purpose: a tiny package that matches its repository, a
 * package published from a build, one with a legitimate install script, and a
 * couple of ordinary libraries.
 */
const DEMO_PACKAGES: Array<{ name: string; version: string }> = [
  { name: 'ms', version: '2.1.3' },
  { name: 'left-pad', version: '1.3.0' },
  { name: 'lodash', version: '4.17.21' },
  { name: 'esbuild', version: '0.28.2' },
  { name: 'chalk', version: '5.3.0' },
  { name: 'semver', version: '7.6.3' },
];

async function main(): Promise<void> {
  const before = await prisma.rule.count();

  let created = 0;
  let updated = 0;

  for (const rule of SEED_RULES) {
    const existing = await prisma.rule.findUnique({
      where: { ruleId: rule.ruleId },
      select: { id: true },
    });

    const content = {
      family: rule.family,
      name: rule.name,
      description: rule.description,
      severity: rule.severity,
      baseWeight: rule.baseWeight,
      remediation: rule.remediation,
      references: rule.references,
    };

    if (existing) {
      await prisma.rule.update({ where: { ruleId: rule.ruleId }, data: content });
      updated += 1;
    } else {
      await prisma.rule.create({
        data: {
          ruleId: rule.ruleId,
          ...content,
          enabled: true,
          falsePositiveNotes: rule.falsePositiveNotes ?? null,
        },
      });
      created += 1;
    }
  }

  const after = await prisma.rule.count();

  console.log(`rules before   ${before}`);
  console.log(`rules created  ${created}`);
  console.log(`rules updated  ${updated}`);
  console.log(`rules total    ${after}`);

  if (after < SEED_RULES.length) {
    throw new Error(
      `catalogue is short: expected at least ${SEED_RULES.length} rules, found ${after}`,
    );
  }

  if (process.env.SEED_DEMO_ACCOUNT === 'true') {
    await seedDemoAccount();
  } else {
    const users = await prisma.user.count();
    if (users === 0) {
      console.log('\nno users yet — register the first account at /register');
      console.log('or set SEED_DEMO_ACCOUNT=true and DEMO_PASSWORD to seed a read-only demo');
    }
  }
}

/**
 * A read-only account for one specific deployment.
 *
 * VIEWER, deliberately. The role can read every surface in the application and
 * change nothing: it cannot run a scan, edit a policy, release a package from
 * quarantine, decide an exception, or invite anyone. A visitor to a public demo
 * gets the whole product to look at and no way to alter what the next visitor
 * sees.
 */
async function seedDemoAccount(): Promise<void> {
  const password = process.env.DEMO_PASSWORD;

  if (!password) {
    throw new Error('SEED_DEMO_ACCOUNT=true requires DEMO_PASSWORD to be set.');
  }

  // The same gate the registration form applies. A demo account is still an
  // account on a public URL, and this is the one place where it would be
  // tempting to skip the check.
  const policy = await checkPasswordPolicy(password, [DEMO_EMAIL, DEMO_ORG_NAME, 'quarantine']);
  if (!policy.ok) {
    throw new Error(`DEMO_PASSWORD is too weak: ${policy.problems.join(' ')}`);
  }

  const org = await prisma.organization.upsert({
    where: { slug: DEMO_ORG_SLUG },
    update: {},
    create: { name: DEMO_ORG_NAME, slug: DEMO_ORG_SLUG },
  });

  const passwordHash = await hashPassword(password);

  // The password is refreshed on every run so rotating it is a redeploy, not a
  // database session. Nothing else about an existing row is touched.
  const user = await prisma.user.upsert({
    where: { email: DEMO_EMAIL },
    update: { passwordHash, name: DEMO_NAME },
    create: {
      email: DEMO_EMAIL,
      name: DEMO_NAME,
      passwordHash,
      // Verified at creation: there is no inbox behind this address, and an
      // unverified account cannot sign in.
      emailVerifiedAt: new Date(),
      totpEnabled: false,
    },
  });

  const membership = await prisma.membership.findFirst({
    where: { userId: user.id, orgId: org.id },
    select: { id: true, role: true },
  });

  if (!membership) {
    await prisma.membership.create({
      data: { userId: user.id, orgId: org.id, role: Role.VIEWER },
    });
  } else if (membership.role !== Role.VIEWER) {
    // Someone promoted the demo account. Put it back.
    await prisma.membership.update({ where: { id: membership.id }, data: { role: Role.VIEWER } });
    console.log('demo account role reset to VIEWER');
  }

  console.log(`\ndemo account   ${DEMO_EMAIL} — ${DEMO_NAME} (VIEWER) in ${DEMO_ORG_NAME}`);
  console.log('password       from DEMO_PASSWORD, not stored in the repository');

  await seedDemoAnalyses(org.id);
}

/**
 * Run a handful of real analyses so the demo dashboard has something in it.
 *
 * Bounded and forgiving: each package is analysed in turn, a failure is
 * reported and skipped rather than failing the deploy, and an existing
 * completed analysis is reused rather than re-run. Roughly twenty seconds of
 * network on a cold database, and nothing at all on a second run.
 */
async function seedDemoAnalyses(orgId: string): Promise<void> {
  const ctx = analysisService.systemContext(orgId);

  const completed = await prisma.analysis.count({
    where: { orgId, verdict: { not: null } },
  });

  if (completed >= DEMO_PACKAGES.length) {
    console.log(`analyses       ${completed} already present, skipping`);
    return;
  }

  console.log(`analyses       running ${DEMO_PACKAGES.length} real scans…`);

  for (const target of DEMO_PACKAGES) {
    try {
      const queued = await analysisService.queueAnalysis(ctx, {
        ecosystem: Ecosystem.NPM,
        name: target.name,
        version: target.version,
      });

      if (queued.reused) {
        console.log(`  ${target.name}@${target.version} — already analysed`);
        continue;
      }

      const result = await analysisService.runAnalysis(ctx, queued.analysisId);
      console.log(
        `  ${target.name}@${target.version} — ${result?.verdict ?? 'no verdict'}` +
          (result ? ` (score ${result.weightedScore.toFixed(1)})` : ''),
      );
    } catch (error) {
      // A registry hiccup or an exhausted GitHub rate limit must not fail the
      // deploy. The dashboard is simply thinner than intended.
      console.warn(`  ${target.name}@${target.version} — skipped: ${(error as Error).message}`);
    }
  }
}

main()
  .catch((error: unknown) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
