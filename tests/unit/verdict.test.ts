import { describe, expect, it } from 'vitest';

import {
  CONFIDENCE_CORROBORATION_BONUS,
  CONFIDENCE_INCOMPLETENESS_PENALTY,
  CONFIDENCE_MAX,
  CONFIDENCE_MIN,
  HARD_TRIGGER_MINIMUM_VERDICT,
  VERDICT_THRESHOLDS,
} from '@/lib/engine/thresholds';
import type { RuleDefinition, Signal, SignalFamily } from '@/lib/engine/types';
import {
  HARD_TRIGGERS,
  bucketForScore,
  computeConfidence,
  computeScore,
  decideVerdict,
  evaluateHardTriggers,
  verdictRank,
  worstVerdict,
} from '@/lib/engine/verdict';

/**
 * The verdict model is the one place where every other part of the engine is
 * reduced to a single word a developer acts on. These tests pin the two things
 * that word depends on: which combinations force a minimum verdict, and where
 * the score buckets actually divide.
 *
 * Nothing here touches a package. The inputs are hand-built Signal objects.
 */

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

const FAMILY_OF: Record<string, SignalFamily> = {
  INS: 'INSTALL',
  OBF: 'OBFUSCATION',
  CAP: 'CAPABILITY',
  TYP: 'TYPOSQUAT',
  MNT: 'MAINTAINER',
  PRV: 'PROVENANCE',
};

function familyFor(ruleId: string): SignalFamily {
  const prefix = ruleId.split('-')[1] ?? 'INS';
  return FAMILY_OF[prefix] ?? 'INSTALL';
}

function fired(ruleId: string, overrides: Partial<Signal> = {}): Signal {
  return {
    ruleId,
    family: familyFor(ruleId),
    fired: true,
    confidence: 1,
    contextModifier: 1,
    evidence: [],
    ...overrides,
  };
}

function passed(ruleId: string, overrides: Partial<Signal> = {}): Signal {
  return { ...fired(ruleId, overrides), fired: false, confidence: 0 };
}

function rules(signals: Signal[], baseWeight = 10): Map<string, RuleDefinition> {
  const map = new Map<string, RuleDefinition>();
  for (const signal of signals) {
    map.set(signal.ruleId, {
      ruleId: signal.ruleId,
      family: signal.family,
      name: signal.ruleId,
      description: signal.ruleId,
      severity: 'MEDIUM',
      baseWeight,
      enabled: true,
    });
  }
  return map;
}

/** Signals that carry exactly `score` in weighted total, at weight 1 each. */
function signalsWorth(score: number): { signals: Signal[]; rules: Map<string, RuleDefinition> } {
  const signals = [fired('Q-TYP-001', { confidence: 1, contextModifier: 1 })];
  const map = rules(signals, score);
  return { signals, rules: map };
}

// ---------------------------------------------------------------------------
// Hard triggers
// ---------------------------------------------------------------------------

describe('hard triggers', () => {
  it('defines exactly the seven documented combinations', () => {
    expect(HARD_TRIGGERS.map((trigger) => trigger.id)).toEqual([
      'install-network-exfil',
      'install-credential-read',
      'install-decoded-payload',
      'tarball-only-executable',
      'exfil-endpoint-with-credentials',
      'obfuscated-exec-with-exfil',
      'trojan-source',
    ]);
  });

  it('gives every trigger a rationale, because a verdict has to be explainable', () => {
    for (const trigger of HARD_TRIGGERS) {
      expect(trigger.label.length).toBeGreaterThan(0);
      expect(trigger.rationale.length).toBeGreaterThan(40);
    }
  });

  describe('install-network-exfil', () => {
    it('fires on a lifecycle script that also reaches the network', () => {
      const hits = evaluateHardTriggers([fired('Q-INS-001'), fired('Q-INS-005')]);
      expect(hits.map((hit) => hit.id)).toContain('install-network-exfil');
    });

    it('reports both rules as load-bearing', () => {
      const hits = evaluateHardTriggers([fired('Q-INS-001'), fired('Q-INS-005')]);
      const hit = hits.find((candidate) => candidate.id === 'install-network-exfil');
      expect(hit?.ruleIds).toEqual(['Q-INS-001', 'Q-INS-005']);
    });

    it('does not fire on a network call with no install hook', () => {
      const hits = evaluateHardTriggers([fired('Q-INS-005')]);
      expect(hits).toEqual([]);
    });

    it('does not fire on an install hook alone', () => {
      const hits = evaluateHardTriggers([fired('Q-INS-001')]);
      expect(hits).toEqual([]);
    });

    it('ignores a rule that was evaluated and did not fire', () => {
      const hits = evaluateHardTriggers([fired('Q-INS-001'), passed('Q-INS-005')]);
      expect(hits).toEqual([]);
    });
  });

  describe('install-credential-read', () => {
    it('fires on an install hook that touches credentials', () => {
      const hits = evaluateHardTriggers([fired('Q-INS-001'), fired('Q-INS-004')]);
      expect(hits.map((hit) => hit.id)).toEqual(['install-credential-read']);
    });

    it('does not fire on a credential read outside install time', () => {
      expect(evaluateHardTriggers([fired('Q-INS-004')])).toEqual([]);
    });
  });

  describe('install-decoded-payload', () => {
    it('fires when decoding is paired with an interpreter', () => {
      const hits = evaluateHardTriggers([
        fired('Q-INS-001'),
        fired('Q-INS-003'),
        fired('Q-INS-002'),
      ]);
      expect(hits.map((hit) => hit.id)).toContain('install-decoded-payload');
    });

    it('accepts dynamic evaluation as the alternative half', () => {
      const hits = evaluateHardTriggers([
        fired('Q-INS-001'),
        fired('Q-INS-003'),
        fired('Q-OBF-003'),
      ]);
      expect(hits.map((hit) => hit.id)).toContain('install-decoded-payload');
    });

    it('does not fire on decoding alone at install time', () => {
      const hits = evaluateHardTriggers([fired('Q-INS-001'), fired('Q-INS-003')]);
      expect(hits.map((hit) => hit.id)).not.toContain('install-decoded-payload');
    });

    it('names the alternative that fired when only one of them did', () => {
      const hits = evaluateHardTriggers([
        fired('Q-INS-001'),
        fired('Q-INS-003'),
        fired('Q-OBF-003'),
      ]);
      const hit = hits.find((candidate) => candidate.id === 'install-decoded-payload');
      expect(hit?.ruleIds).toEqual(['Q-INS-001', 'Q-INS-003', 'Q-OBF-003']);
    });

    it('drops a redundant alternative when both halves fired', () => {
      const hits = evaluateHardTriggers([
        fired('Q-INS-001'),
        fired('Q-INS-003'),
        fired('Q-INS-002'),
        fired('Q-OBF-003'),
      ]);
      const hit = hits.find((candidate) => candidate.id === 'install-decoded-payload');
      // The probe reports the rules whose removal actually stops the trigger.
      // With both alternatives present neither is individually load-bearing, so
      // only the conjunction survives — claiming otherwise would overstate what
      // the trigger depended on.
      expect(hit?.ruleIds).toEqual(['Q-INS-001', 'Q-INS-003']);
    });
  });

  describe('tarball-only-executable', () => {
    it('fires on Q-PRV-003 alone — the event-stream signature', () => {
      const hits = evaluateHardTriggers([fired('Q-PRV-003')]);
      expect(hits.map((hit) => hit.id)).toEqual(['tarball-only-executable']);
      expect(hits[0]?.ruleIds).toEqual(['Q-PRV-003']);
    });
  });

  describe('exfil-endpoint-with-credentials', () => {
    it('fires on credential access beside a known exfil endpoint', () => {
      const hits = evaluateHardTriggers([fired('Q-CAP-005'), fired('Q-CAP-008')]);
      expect(hits.map((hit) => hit.id)).toEqual(['exfil-endpoint-with-credentials']);
    });

    it('accepts wallet access as the collection half', () => {
      const hits = evaluateHardTriggers([fired('Q-CAP-006'), fired('Q-CAP-008')]);
      expect(hits.map((hit) => hit.id)).toEqual(['exfil-endpoint-with-credentials']);
    });

    it('does not fire on an exfil endpoint with nothing to exfiltrate', () => {
      expect(evaluateHardTriggers([fired('Q-CAP-008')])).toEqual([]);
    });

    it('does not fire on credential access with no delivery', () => {
      expect(evaluateHardTriggers([fired('Q-CAP-005')])).toEqual([]);
    });
  });

  describe('obfuscated-exec-with-exfil', () => {
    it('fires on obfuscation plus command execution plus network', () => {
      const hits = evaluateHardTriggers([
        fired('Q-OBF-004'),
        fired('Q-CAP-001'),
        fired('Q-CAP-002'),
      ]);
      expect(hits.map((hit) => hit.id)).toEqual(['obfuscated-exec-with-exfil']);
    });

    it('does not fire on exec and network without obfuscation', () => {
      const hits = evaluateHardTriggers([fired('Q-CAP-001'), fired('Q-CAP-002')]);
      expect(hits).toEqual([]);
    });

    it('does not fire on obfuscation and exec without network', () => {
      const hits = evaluateHardTriggers([fired('Q-OBF-003'), fired('Q-CAP-001')]);
      expect(hits).toEqual([]);
    });
  });

  describe('trojan-source', () => {
    it('fires on Q-OBF-005 alone', () => {
      const hits = evaluateHardTriggers([fired('Q-OBF-005')]);
      expect(hits.map((hit) => hit.id)).toEqual(['trojan-source']);
    });
  });

  it('reports every trigger a package satisfies, not just the first', () => {
    const hits = evaluateHardTriggers([
      fired('Q-INS-001'),
      fired('Q-INS-004'),
      fired('Q-INS-005'),
      fired('Q-OBF-005'),
    ]);
    expect(hits.map((hit) => hit.id).sort()).toEqual([
      'install-credential-read',
      'install-network-exfil',
      'trojan-source',
    ]);
  });

  it('fires nothing on an empty signal set', () => {
    expect(evaluateHardTriggers([])).toEqual([]);
  });

  it('fires nothing on a package where every rule passed', () => {
    const signals = ['Q-INS-001', 'Q-CAP-008', 'Q-OBF-005', 'Q-PRV-003'].map((id) => passed(id));
    expect(evaluateHardTriggers(signals)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Score
// ---------------------------------------------------------------------------

describe('computeScore', () => {
  it('multiplies weight by confidence by context modifier', () => {
    const signals = [fired('Q-CAP-001', { confidence: 0.5, contextModifier: 0.3 })];
    const { total, contributions } = computeScore(signals, rules(signals, 20));

    expect(total).toBeCloseTo(20 * 0.5 * 0.3, 10);
    expect(contributions).toHaveLength(1);
    expect(contributions[0]).toMatchObject({ ruleId: 'Q-CAP-001', weight: 20 });
  });

  it('sums across fired signals and ignores the rest', () => {
    const signals = [
      fired('Q-CAP-001', { confidence: 1, contextModifier: 1 }),
      passed('Q-CAP-002'),
      fired('Q-OBF-003', { confidence: 0.5, contextModifier: 1 }),
    ];
    expect(computeScore(signals, rules(signals, 10)).total).toBeCloseTo(15, 10);
  });

  it('ignores a signal whose rule is disabled in the catalogue', () => {
    const signals = [fired('Q-CAP-001'), fired('Q-CAP-002')];
    const map = rules(signals, 10);
    map.set('Q-CAP-002', { ...map.get('Q-CAP-002')!, enabled: false });

    expect(computeScore(signals, map).total).toBeCloseTo(10, 10);
  });

  it('ignores a signal with no rule in the catalogue at all', () => {
    const signals = [fired('Q-CAP-001'), fired('Q-XXX-999')];
    const map = rules([signals[0]!], 10);
    expect(computeScore(signals, map).total).toBeCloseTo(10, 10);
  });

  it('orders contributions by weight so the report leads with what mattered', () => {
    const signals = [
      fired('Q-OBF-001', { confidence: 0.2 }),
      fired('Q-CAP-001', { confidence: 0.9 }),
      fired('Q-INS-001', { confidence: 0.5 }),
    ];
    const { contributions } = computeScore(signals, rules(signals, 10));
    expect(contributions.map((entry) => entry.ruleId)).toEqual([
      'Q-CAP-001',
      'Q-INS-001',
      'Q-OBF-001',
    ]);
  });

  it('scores an empty analysis at zero', () => {
    expect(computeScore([], new Map()).total).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Buckets
// ---------------------------------------------------------------------------

describe('bucketForScore', () => {
  it('places each threshold value in its own bucket, inclusive of the floor', () => {
    expect(bucketForScore(VERDICT_THRESHOLDS.KNOWN_MALICIOUS)).toBe('KNOWN_MALICIOUS');
    expect(bucketForScore(VERDICT_THRESHOLDS.LIKELY_MALICIOUS)).toBe('LIKELY_MALICIOUS');
    expect(bucketForScore(VERDICT_THRESHOLDS.SUSPICIOUS)).toBe('SUSPICIOUS');
    expect(bucketForScore(VERDICT_THRESHOLDS.LOW_RISK)).toBe('LOW_RISK');
    expect(bucketForScore(VERDICT_THRESHOLDS.CLEAN)).toBe('CLEAN');
  });

  it('drops to the bucket below one unit under each floor', () => {
    expect(bucketForScore(VERDICT_THRESHOLDS.KNOWN_MALICIOUS - 0.001)).toBe('LIKELY_MALICIOUS');
    expect(bucketForScore(VERDICT_THRESHOLDS.LIKELY_MALICIOUS - 0.001)).toBe('SUSPICIOUS');
    expect(bucketForScore(VERDICT_THRESHOLDS.SUSPICIOUS - 0.001)).toBe('LOW_RISK');
    expect(bucketForScore(VERDICT_THRESHOLDS.LOW_RISK - 0.001)).toBe('CLEAN');
  });

  it('keeps the thresholds strictly ordered', () => {
    expect(VERDICT_THRESHOLDS.KNOWN_MALICIOUS).toBeGreaterThan(VERDICT_THRESHOLDS.LIKELY_MALICIOUS);
    expect(VERDICT_THRESHOLDS.LIKELY_MALICIOUS).toBeGreaterThan(VERDICT_THRESHOLDS.SUSPICIOUS);
    expect(VERDICT_THRESHOLDS.SUSPICIOUS).toBeGreaterThan(VERDICT_THRESHOLDS.LOW_RISK);
    expect(VERDICT_THRESHOLDS.LOW_RISK).toBeGreaterThan(VERDICT_THRESHOLDS.CLEAN);
  });

  it('treats an arbitrarily large score as KNOWN_MALICIOUS rather than overflowing', () => {
    expect(bucketForScore(10_000)).toBe('KNOWN_MALICIOUS');
  });

  it('treats a negative score as CLEAN', () => {
    expect(bucketForScore(-5)).toBe('CLEAN');
  });
});

describe('verdict ordering', () => {
  it('ranks the worst verdict lowest, so min() picks the worse one', () => {
    expect(verdictRank('KNOWN_MALICIOUS')).toBe(0);
    expect(verdictRank('CLEAN')).toBe(4);
  });

  it('picks the worse of two verdicts either way round', () => {
    expect(worstVerdict('CLEAN', 'SUSPICIOUS')).toBe('SUSPICIOUS');
    expect(worstVerdict('SUSPICIOUS', 'CLEAN')).toBe('SUSPICIOUS');
    expect(worstVerdict('LOW_RISK', 'LOW_RISK')).toBe('LOW_RISK');
  });
});

// ---------------------------------------------------------------------------
// Confidence
// ---------------------------------------------------------------------------

describe('computeConfidence', () => {
  it('reports a complete, empty analysis as a confident clean', () => {
    expect(computeConfidence({ signals: [passed('Q-CAP-001')], incompleteStages: [] })).toBeCloseTo(
      0.9,
      10,
    );
  });

  it('lowers a clean result for each stage that could not run', () => {
    const confidence = computeConfidence({
      signals: [passed('Q-CAP-001')],
      incompleteStages: ['PROVENANCE'],
    });
    expect(confidence).toBeCloseTo(0.9 - CONFIDENCE_INCOMPLETENESS_PENALTY, 10);
  });

  it('averages the confidence of what fired', () => {
    const signals = [
      fired('Q-CAP-001', { confidence: 0.6 }),
      fired('Q-CAP-002', { confidence: 0.8 }),
    ];
    // One family, so no corroboration bonus.
    expect(computeConfidence({ signals, incompleteStages: [] })).toBeCloseTo(0.7, 10);
  });

  it('adds a corroboration bonus for each additional family that fired', () => {
    const oneFamily = [fired('Q-CAP-001', { confidence: 0.6 })];
    const twoFamilies = [...oneFamily, fired('Q-OBF-003', { confidence: 0.6 })];

    const single = computeConfidence({ signals: oneFamily, incompleteStages: [] });
    const paired = computeConfidence({ signals: twoFamilies, incompleteStages: [] });

    expect(paired - single).toBeCloseTo(CONFIDENCE_CORROBORATION_BONUS, 10);
  });

  it('penalises individually skipped rules less than a whole failed family', () => {
    const signals = [
      fired('Q-CAP-001', { confidence: 0.8 }),
      { ...passed('Q-PRV-003'), skipped: 'NO_REPO' as const },
    ];

    const withSkip = computeConfidence({ signals, incompleteStages: [] });
    const withStage = computeConfidence({ signals: [signals[0]!], incompleteStages: ['PROV'] });

    expect(withSkip).toBeGreaterThan(withStage);
  });

  it('clamps to the confidence floor rather than going negative', () => {
    const confidence = computeConfidence({
      signals: [passed('Q-CAP-001')],
      incompleteStages: Array.from({ length: 40 }, (_, index) => `stage-${index}`),
    });
    expect(confidence).toBe(CONFIDENCE_MIN);
  });

  it('clamps to the ceiling rather than exceeding 1', () => {
    const signals = [
      fired('Q-INS-001', { confidence: 1 }),
      fired('Q-OBF-003', { confidence: 1 }),
      fired('Q-CAP-001', { confidence: 1 }),
      fired('Q-PRV-003', { confidence: 1 }),
    ];
    expect(computeConfidence({ signals, incompleteStages: [] })).toBe(CONFIDENCE_MAX);
  });
});

// ---------------------------------------------------------------------------
// decideVerdict
// ---------------------------------------------------------------------------

describe('decideVerdict', () => {
  it('returns CLEAN with a full score breakdown when nothing fired', () => {
    const outcome = decideVerdict({
      signals: [passed('Q-CAP-001')],
      rules: rules([passed('Q-CAP-001')]),
      incompleteStages: [],
    });

    expect(outcome.verdict).toBe('CLEAN');
    expect(outcome.weightedScore).toBe(0);
    expect(outcome.decidedBy).toBe('weighted-score');
    expect(outcome.hardTriggers).toEqual([]);
  });

  it('buckets by weighted score when no hard trigger fires', () => {
    const { signals, rules: map } = signalsWorth(VERDICT_THRESHOLDS.SUSPICIOUS);
    const outcome = decideVerdict({ signals, rules: map, incompleteStages: [] });

    expect(outcome.verdict).toBe('SUSPICIOUS');
    expect(outcome.decidedBy).toBe('weighted-score');
  });

  it('forces LIKELY_MALICIOUS from a hard trigger even at a trivial score', () => {
    const signals = [fired('Q-OBF-005', { confidence: 0.95 })];
    const outcome = decideVerdict({
      signals,
      rules: rules(signals, 1),
      incompleteStages: [],
    });

    expect(outcome.weightedScore).toBeLessThan(VERDICT_THRESHOLDS.LOW_RISK);
    expect(outcome.verdict).toBe(HARD_TRIGGER_MINIMUM_VERDICT);
    expect(outcome.decidedBy).toBe('hard-trigger');
  });

  it('keeps the worse verdict when the score already exceeds the trigger minimum', () => {
    const signals = [fired('Q-OBF-005', { confidence: 1 })];
    const outcome = decideVerdict({
      signals,
      rules: rules(signals, VERDICT_THRESHOLDS.KNOWN_MALICIOUS),
      incompleteStages: [],
    });

    expect(outcome.verdict).toBe('KNOWN_MALICIOUS');
    // The score, not the trigger, is what set the verdict.
    expect(outcome.decidedBy).toBe('weighted-score');
    expect(outcome.hardTriggers.map((hit) => hit.id)).toEqual(['trojan-source']);
  });

  it('lets a corpus hash match assert KNOWN_MALICIOUS at full confidence', () => {
    const outcome = decideVerdict({
      signals: [passed('Q-CAP-001')],
      rules: rules([passed('Q-CAP-001')]),
      incompleteStages: ['PROVENANCE'],
      knownBadHashMatch: true,
    });

    expect(outcome.verdict).toBe('KNOWN_MALICIOUS');
    expect(outcome.confidence).toBe(CONFIDENCE_MAX);
    expect(outcome.decidedBy).toBe('known-bad-hash');
  });

  it('still reports the hard triggers alongside a hash match', () => {
    const signals = [fired('Q-PRV-003')];
    const outcome = decideVerdict({
      signals,
      rules: rules(signals),
      incompleteStages: [],
      knownBadHashMatch: true,
    });

    expect(outcome.decidedBy).toBe('known-bad-hash');
    expect(outcome.hardTriggers.map((hit) => hit.id)).toEqual(['tarball-only-executable']);
  });

  it('reports confidence separately from the verdict and never lets it soften one', () => {
    const signals = [fired('Q-OBF-005', { confidence: CONFIDENCE_MIN })];
    const outcome = decideVerdict({
      signals,
      rules: rules(signals, 1),
      incompleteStages: ['PROVENANCE', 'MAINTAINER'],
    });

    expect(outcome.confidence).toBeLessThan(0.5);
    expect(outcome.verdict).toBe(HARD_TRIGGER_MINIMUM_VERDICT);
  });

  it('applies the context modifier, so the same signal is worth less in a build tool', () => {
    const utility = [fired('Q-CAP-001', { confidence: 1, contextModifier: 1 })];
    const buildTool = [fired('Q-CAP-001', { confidence: 1, contextModifier: 0.3 })];

    const strict = decideVerdict({
      signals: utility,
      rules: rules(utility, VERDICT_THRESHOLDS.SUSPICIOUS),
      incompleteStages: [],
    });
    const lenient = decideVerdict({
      signals: buildTool,
      rules: rules(buildTool, VERDICT_THRESHOLDS.SUSPICIOUS),
      incompleteStages: [],
    });

    expect(strict.verdict).toBe('SUSPICIOUS');
    expect(lenient.verdict).not.toBe('SUSPICIOUS');
    expect(lenient.weightedScore).toBeLessThan(strict.weightedScore);
  });
});
