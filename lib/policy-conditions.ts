import { z } from 'zod';

import { SIGNAL_FAMILIES, VERDICTS, VERDICT_META } from '@/lib/constants';

/**
 * What a policy condition is, and how to say it in English.
 *
 * This lives outside `lib/services/policy.service.ts` because the condition
 * builder and the policy list are client components: importing the service to
 * reach `describeCondition` would drag Prisma, pino and `node:crypto` into the
 * browser bundle, which webpack refuses outright. The service imports these and
 * re-exports them, so the shapes stored, evaluated and rendered are one
 * definition rather than two that can drift.
 *
 * The enum members are spelled as string unions rather than pulled from Prisma
 * for the same reason. They are the same values — `prisma/schema.prisma` and
 * `lib/constants.ts` are checked against each other by the constants test.
 */

const ECOSYSTEMS = ['NPM', 'PYPI'] as const;

const ruleIdSchema = z
  .string()
  .trim()
  .regex(/^Q-[A-Z]{3}-\d{3}$/, 'Rule ids look like Q-CAP-001.');

export const policyConditionSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('verdict_at_least'),
    verdict: z.enum(VERDICTS),
  }),
  z.object({
    type: z.literal('rule_fired'),
    ruleId: ruleIdSchema,
  }),
  z.object({
    type: z.literal('family_score_at_least'),
    family: z.enum(SIGNAL_FAMILIES),
    score: z.number().min(0).max(100),
  }),
  z.object({
    type: z.literal('package_age_below_days'),
    days: z.number().int().min(1).max(3650),
  }),
  z.object({
    type: z.literal('maintainer_count_below'),
    count: z.number().int().min(1).max(100),
  }),
  z.object({
    type: z.literal('license_not_in'),
    licenses: z.array(z.string().trim().min(1).max(64)).min(1).max(40),
  }),
  z.object({
    type: z.literal('ecosystem_is'),
    ecosystem: z.enum(ECOSYSTEMS),
  }),
]);

export type PolicyCondition = z.infer<typeof policyConditionSchema>;
export type PolicyConditionType = PolicyCondition['type'];

export const CONDITION_TYPES = [
  'verdict_at_least',
  'rule_fired',
  'family_score_at_least',
  'package_age_below_days',
  'maintainer_count_below',
  'license_not_in',
  'ecosystem_is',
] as const satisfies readonly PolicyConditionType[];

export const CONDITION_LABELS: Record<PolicyConditionType, string> = {
  verdict_at_least: 'Verdict is at least',
  rule_fired: 'A specific rule fired',
  family_score_at_least: 'Signal family score is at least',
  package_age_below_days: 'Package is younger than',
  maintainer_count_below: 'Maintainer count is below',
  license_not_in: 'Licence is not one of',
  ecosystem_is: 'Registry is',
};

/** One-line English for a condition, used on the list, the report and the diff. */
export function describeCondition(condition: PolicyCondition): string {
  switch (condition.type) {
    case 'verdict_at_least':
      return `verdict is ${VERDICT_META[condition.verdict].label} or worse`;
    case 'rule_fired':
      return `rule ${condition.ruleId} fired`;
    case 'family_score_at_least':
      return `${condition.family.toLowerCase()} score ≥ ${condition.score}`;
    case 'package_age_below_days':
      return `package first published less than ${condition.days} days ago`;
    case 'maintainer_count_below':
      return `fewer than ${condition.count} maintainers`;
    case 'license_not_in':
      return `licence not in ${condition.licenses.join(', ')}`;
    case 'ecosystem_is':
      return `registry is ${condition.ecosystem === 'NPM' ? 'npm' : 'PyPI'}`;
  }
}
