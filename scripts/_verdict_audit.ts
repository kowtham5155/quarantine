import {
  HARD_TRIGGERS,
  bucketForScore,
  computeConfidence,
  computeScore,
  decideVerdict,
  evaluateHardTriggers,
} from '../lib/engine/verdict';
import { VERDICT_THRESHOLDS } from '../lib/engine/thresholds';
import { SEED_RULES } from '../prisma/seed-data/rules';
import type { RuleDefinition, Signal } from '../lib/engine/types';

const rules = new Map<string, RuleDefinition>(
  SEED_RULES.map((r) => [r.ruleId, { ruleId: r.ruleId, family: r.family, baseWeight: r.baseWeight, severity: r.severity, enabled: true } as RuleDefinition]),
);

const sig = (ruleId: string, fired: boolean, confidence = 1, contextModifier = 1): Signal => ({
  ruleId,
  family: (SEED_RULES.find((r) => r.ruleId === ruleId)?.family ?? 'CAPABILITY') as Signal['family'],
  fired,
  confidence,
  contextModifier,
  evidence: [],
});

console.log('### 5a. zero signals -> CLEAN?');
const none = SEED_RULES.map((r) => sig(r.ruleId, false));
const z = decideVerdict({ signals: none, rules, incompleteStages: [] });
console.log(`   verdict=${z.verdict} score=${z.weightedScore} confidence=${z.confidence.toFixed(3)} decidedBy=${z.decidedBy}`);

console.log('\n### 5b. each hard trigger alone -> at least LIKELY_MALICIOUS?');
for (const trigger of HARD_TRIGGERS) {
  // Find the minimal fired-set that satisfies this trigger by brute force over its rules.
  const candidates = SEED_RULES.map((r) => r.ruleId);
  let found: string[] | null = null;
  const tryset = (ids: string[]) => {
    const s = new Set(ids);
    return HARD_TRIGGERS.filter((t) => t.test(s)).map((t) => t.id);
  };
  outer: for (let n = 1; n <= 3 && !found; n++) {
    const combo = (start: number, acc: string[]): boolean => {
      if (acc.length === n) {
        const hits = tryset(acc);
        if (hits.includes(trigger.id)) { found = [...acc]; return true; }
        return false;
      }
      for (let i = start; i < candidates.length; i++) {
        if (combo(i + 1, [...acc, candidates[i]!])) return true;
      }
      return false;
    };
    if (combo(0, [])) break outer;
  }
  if (!found) { console.log(`   ${trigger.id}: NO SATISFYING RULE SET FOUND (dead trigger?)`); continue; }
  const signals = SEED_RULES.map((r) => sig(r.ruleId, found!.includes(r.ruleId)));
  const out = decideVerdict({ signals, rules, incompleteStages: [] });
  const ok = ['LIKELY_MALICIOUS', 'KNOWN_MALICIOUS'].includes(out.verdict);
  console.log(`   ${ok ? 'ok   ' : 'FAIL '} ${trigger.id}: fired=${found.join('+')} -> ${out.verdict} score=${out.weightedScore.toFixed(1)} decidedBy=${out.decidedBy}`);
}

console.log('\n### 5c. bucket boundaries continuous?');
const bounds = [-1, 0, 0.001, 9.999, 10, 10.001, 27.999, 28, 28.001, 54.999, 55, 55.001, 99.999, 100, 100.001, 1e9, NaN, Infinity, -Infinity];
for (const v of bounds) {
  console.log(`   score ${String(v).padStart(9)} -> ${bucketForScore(v)}`);
}

console.log('\n### 5d. confidence vs corroboration');
const mk = (families: number) => {
  const picks = ['Q-INS-001', 'Q-OBF-001', 'Q-CAP-001', 'Q-TYP-001', 'Q-MNT-001', 'Q-PRV-001'].slice(0, families);
  return SEED_RULES.map((r) => sig(r.ruleId, picks.includes(r.ruleId), 0.8));
};
for (let f = 0; f <= 6; f++) {
  const c = computeConfidence({ signals: mk(f), incompleteStages: [] });
  console.log(`   ${f} families firing -> confidence ${c.toFixed(3)}`);
}
console.log('   with 1 incomplete stage, 3 families:', computeConfidence({ signals: mk(3), incompleteStages: ['repository'] }).toFixed(3));
console.log('   with 3 incomplete stages, 3 families:', computeConfidence({ signals: mk(3), incompleteStages: ['a','b','c'] }).toFixed(3));

console.log('\n### 5e. thresholds sanity');
console.log('   ', JSON.stringify(VERDICT_THRESHOLDS));
const maxPossible = SEED_RULES.reduce((t, r) => t + r.baseWeight, 0);
console.log(`   sum of every rule weight = ${maxPossible} (KNOWN_MALICIOUS floor is ${VERDICT_THRESHOLDS.KNOWN_MALICIOUS})`);
const allFired = SEED_RULES.map((r) => sig(r.ruleId, true));
console.log(`   every rule firing -> score ${computeScore(allFired, rules).total.toFixed(1)}, verdict ${decideVerdict({ signals: allFired, rules, incompleteStages: [] }).verdict}`);
