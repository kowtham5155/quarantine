import { cache } from 'react';

import { requireAuthContext } from '@/lib/auth-context';
import * as ruleService from '@/lib/services/rule.service';

import type { RuleOption } from './ConditionBuilder';

/**
 * The rule catalogue, trimmed to what the condition builder needs.
 *
 * Only enabled rules are offered: a policy keyed on a disabled rule would never
 * fire, and a builder that lets you write one is a trap.
 */
export const loadRuleOptions = cache(async (): Promise<RuleOption[]> => {
  const ctx = await requireAuthContext();
  const rules = await ruleService.listRules(ctx);

  return rules
    .filter((rule) => rule.enabled)
    .map((rule) => ({ ruleId: rule.ruleId, name: rule.name }));
});
