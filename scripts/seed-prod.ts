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
 */
import { PrismaClient } from '@prisma/client';

import { SEED_RULES } from '../prisma/seed-data/rules';

const prisma = new PrismaClient();

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

  // The first account is created through /register, which makes its org and
  // makes that user its owner. No default credentials are seeded: this script
  // runs against a deployment with a public URL, and a known password on a
  // public URL is not a demo convenience, it is an open door.
  const users = await prisma.user.count();
  if (users === 0) {
    console.log('\nno users yet — register the first account at /register');
  }
}

main()
  .catch((error: unknown) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
