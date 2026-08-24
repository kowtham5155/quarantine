import { VERDICTS, type Verdict } from '@/lib/constants';
import {
  CONFIDENCE_CORROBORATION_BONUS,
  CONFIDENCE_INCOMPLETENESS_PENALTY,
  CONFIDENCE_MAX,
  CONFIDENCE_MIN,
  HARD_TRIGGER_MINIMUM_VERDICT,
  VERDICT_THRESHOLDS,
} from '@/lib/engine/thresholds';
import type { HardTriggerHit, RuleDefinition, Signal } from '@/lib/engine/types';

/**
 * The hybrid verdict model.
 *
 * A weighted score alone is too easy to game: spread the behaviour across
 * enough low-weight rules and nothing crosses a threshold. A pure rule-match
 * model is too brittle: one novel technique and it sees nothing. So the engine
 * runs both, and the worse of the two answers wins.
 *
 *   1. **Hard triggers.** Combinations with no benign explanation. Any hit
 *      forces at least LIKELY_MALICIOUS regardless of score.
 *   2. **Weighted score.** Σ(weight × confidence × contextModifier) over fired
 *      signals, bucketed by VERDICT_THRESHOLDS.
 *
 * Confidence is reported separately from the verdict and never changes it. A
 * low-confidence LIKELY_MALICIOUS still says "do not install"; it just also
 * says "and here is how much of the picture we could actually see".
 */

// ---------------------------------------------------------------------------
// Hard triggers
// ---------------------------------------------------------------------------

export interface HardTrigger {
  id: string;
  label: string;
  /** Human explanation of why this combination has no innocent reading. */
  rationale: string;
  /** Fires when this predicate holds over the set of fired rule ids. */
  test: (fired: ReadonlySet<string>) => boolean;
}

const has = (fired: ReadonlySet<string>, ...ruleIds: string[]): boolean =>
  ruleIds.every((ruleId) => fired.has(ruleId));

const any = (fired: ReadonlySet<string>, ...ruleIds: string[]): boolean =>
  ruleIds.some((ruleId) => fired.has(ruleId));

/**
 * Combinations that force a minimum verdict.
 *
 * Each of these is a behaviour, not a heuristic: a description of something the
 * package *does* that no legitimate package does. Adding to this list is a
 * serious decision — a false positive here is a package the user is told not to
 * install, and the cost of being wrong is high.
 */
export const HARD_TRIGGERS: HardTrigger[] = [
  {
    id: 'install-network-exfil',
    label: 'Install script makes an outbound network call',
    rationale:
      'A lifecycle script that runs automatically on install and also reaches the network is the shape of every dropper in the ecosystem. There is no legitimate reason for a dependency to phone home before its code is ever imported.',
    test: (fired) => has(fired, 'Q-INS-001', 'Q-INS-005'),
  },
  {
    id: 'install-credential-read',
    label: 'Install script reads credentials',
    rationale:
      'A script that runs at install time and touches ~/.ssh, ~/.aws, .npmrc or .env is harvesting secrets. Nothing a package legitimately needs at install time lives in those files.',
    test: (fired) => has(fired, 'Q-INS-001', 'Q-INS-004'),
  },
  {
    id: 'install-decoded-payload',
    label: 'Install script decodes and executes a payload',
    rationale:
      'Decoding a blob and handing it to an interpreter during install is obfuscation with intent. A build step that genuinely needs to run code ships that code readably.',
    test: (fired) => has(fired, 'Q-INS-001', 'Q-INS-003') && any(fired, 'Q-INS-002', 'Q-OBF-003'),
  },
  {
    id: 'tarball-only-executable',
    label: 'Executable code in the tarball is absent from the source repository',
    rationale:
      'This is the event-stream signature. Code that reviewers never saw, shipped to every machine that installs the package. There is no packaging workflow that produces an unexplained executable file.',
    test: (fired) => fired.has('Q-PRV-003'),
  },
  {
    id: 'exfil-endpoint-with-credentials',
    label: 'Credential access alongside a known exfiltration endpoint',
    rationale:
      'Reading credentials or wallet files in the same package as a Discord/Telegram webhook or an OAST callback host is collection plus delivery. Neither has a benign reading in a dependency.',
    test: (fired) => any(fired, 'Q-CAP-005', 'Q-CAP-006') && fired.has('Q-CAP-008'),
  },
  {
    id: 'obfuscated-exec-with-exfil',
    label: 'Obfuscated code that both executes commands and calls out',
    rationale:
      'Obfuscation, command execution and network access together describe a remote-access payload. Any one alone is explicable; all three are not.',
    test: (fired) =>
      any(fired, 'Q-OBF-003', 'Q-OBF-004') && fired.has('Q-CAP-001') && fired.has('Q-CAP-002'),
  },
  {
    id: 'trojan-source',
    label: 'Bidirectional control characters in source',
    rationale:
      'Trojan Source (CVE-2021-42574) makes source render differently from how it executes, defeating human review by construction. It has no legitimate use in package code.',
    test: (fired) => fired.has('Q-OBF-005'),
  },
];

/** Hard triggers that fired, with the rules that caused each. */
export function evaluateHardTriggers(signals: Signal[]): HardTriggerHit[] {
  const fired = new Set(signals.filter((signal) => signal.fired).map((signal) => signal.ruleId));

  const hits: HardTriggerHit[] = [];
  for (const trigger of HARD_TRIGGERS) {
    if (!trigger.test(fired)) continue;
    hits.push({
      id: trigger.id,
      label: trigger.label,
      ruleIds: loadBearingRules(trigger, fired),
    });
  }
  return hits;
}

/**
 * Which of the fired rules this trigger actually depended on.
 *
 * Probed against the real fired set rather than a maintained parallel list,
 * which would drift out of sync with the predicate: drop each fired rule in
 * turn and keep the ones whose absence stops the trigger firing.
 *
 * For a trigger with alternatives — `any(Q-INS-002, Q-OBF-003)` — no single
 * alternative is individually load-bearing when both fired, so the probe finds
 * none of them. In that case every rule the trigger could have used is
 * reported, because "one of these" is the honest answer.
 */
function loadBearingRules(trigger: HardTrigger, fired: ReadonlySet<string>): string[] {
  const necessary: string[] = [];

  for (const ruleId of fired) {
    const without = new Set(fired);
    without.delete(ruleId);
    if (!trigger.test(without)) necessary.push(ruleId);
  }

  if (necessary.length > 0) return necessary.sort();

  // Every remaining rule is individually redundant, so the trigger rests on a
  // disjunction. Report the fired rules that participate at all.
  return [...fired]
    // Removing the whole rule family the alternative belongs to does stop it.
    .filter((ruleId) => !trigger.test(subtractFamily(fired, ruleId)))
    .sort();
}

/** The fired set without `ruleId` or anything sharing its rule prefix. */
function subtractFamily(fired: ReadonlySet<string>, ruleId: string): Set<string> {
  const prefix = ruleId.slice(0, ruleId.lastIndexOf('-'));
  const out = new Set<string>();
  for (const candidate of fired) {
    if (!candidate.startsWith(prefix)) out.add(candidate);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Weighted score
// ---------------------------------------------------------------------------

export interface ScoreBreakdown {
  total: number;
  /** Per-signal contribution, for the report's arithmetic panel. */
  contributions: Array<{
    ruleId: string;
    weight: number;
    confidence: number;
    contextModifier: number;
    contribution: number;
  }>;
}

/** Σ(weight × confidence × contextModifier) over fired signals. */
export function computeScore(
  signals: Signal[],
  rules: Map<string, RuleDefinition>,
): ScoreBreakdown {
  const contributions: ScoreBreakdown['contributions'] = [];
  let total = 0;

  for (const signal of signals) {
    if (!signal.fired) continue;

    const rule = rules.get(signal.ruleId);
    if (!rule || !rule.enabled) continue;

    const contribution = rule.baseWeight * signal.confidence * signal.contextModifier;
    total += contribution;

    contributions.push({
      ruleId: signal.ruleId,
      weight: rule.baseWeight,
      confidence: signal.confidence,
      contextModifier: signal.contextModifier,
      contribution,
    });
  }

  contributions.sort((a, b) => b.contribution - a.contribution);
  return { total, contributions };
}

/** Bucket a score, checking the highest threshold first. */
export function bucketForScore(score: number): Verdict {
  if (score >= VERDICT_THRESHOLDS.KNOWN_MALICIOUS) return 'KNOWN_MALICIOUS';
  if (score >= VERDICT_THRESHOLDS.LIKELY_MALICIOUS) return 'LIKELY_MALICIOUS';
  if (score >= VERDICT_THRESHOLDS.SUSPICIOUS) return 'SUSPICIOUS';
  if (score >= VERDICT_THRESHOLDS.LOW_RISK) return 'LOW_RISK';
  return 'CLEAN';
}

/** Rank on the verdict scale. 0 is worst, so `min` picks the worse verdict. */
export function verdictRank(verdict: Verdict): number {
  return VERDICTS.indexOf(verdict);
}

/** The worse of two verdicts. */
export function worstVerdict(a: Verdict, b: Verdict): Verdict {
  return verdictRank(a) <= verdictRank(b) ? a : b;
}

// ---------------------------------------------------------------------------
// Confidence
// ---------------------------------------------------------------------------

export interface ConfidenceInput {
  signals: Signal[];
  /** Families or stages that failed or were skipped entirely. */
  incompleteStages: string[];
}

/**
 * How much of the picture the engine actually saw.
 *
 * Three inputs:
 *
 *   - **Signal confidence.** The mean confidence of what fired. A pile of
 *     low-confidence matches is less convincing than one certain match.
 *   - **Corroboration.** Independent families agreeing is the strongest
 *     evidence available. Obfuscation alone is a style choice; obfuscation plus
 *     a credential read plus an install hook is an attack.
 *   - **Completeness.** Every stage that could not run lowers confidence. An
 *     analysis that never reached the repository knows strictly less than one
 *     that did, and should not report a confident CLEAN.
 *
 * When nothing fired, confidence describes how thoroughly the engine was able
 * to look — which is exactly what a CLEAN verdict needs to be read against.
 */
export function computeConfidence({ signals, incompleteStages }: ConfidenceInput): number {
  const fired = signals.filter((signal) => signal.fired);
  const skipped = signals.filter((signal) => signal.skipped && !signal.fired);

  const completenessPenalty =
    incompleteStages.length * CONFIDENCE_INCOMPLETENESS_PENALTY +
    // Individually skipped rules cost less than a whole family failing.
    (skipped.length / Math.max(1, signals.length)) * CONFIDENCE_INCOMPLETENESS_PENALTY;

  if (fired.length === 0) {
    // A clean result from a complete analysis is a confident clean.
    return clamp(0.9 - completenessPenalty);
  }

  const meanConfidence =
    fired.reduce((total, signal) => total + signal.confidence, 0) / fired.length;

  const families = new Set(fired.map((signal) => signal.family));
  const corroboration = Math.max(0, families.size - 1) * CONFIDENCE_CORROBORATION_BONUS;

  return clamp(meanConfidence + corroboration - completenessPenalty);
}

function clamp(value: number): number {
  if (!Number.isFinite(value)) return CONFIDENCE_MIN;
  return Math.min(CONFIDENCE_MAX, Math.max(CONFIDENCE_MIN, value));
}

// ---------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------

export interface VerdictInput {
  signals: Signal[];
  rules: Map<string, RuleDefinition>;
  incompleteStages: string[];
  /** Set when the tarball hash matches a corpus entry labelled malicious. */
  knownBadHashMatch?: boolean;
}

export interface VerdictOutcome {
  verdict: Verdict;
  confidence: number;
  weightedScore: number;
  hardTriggers: HardTriggerHit[];
  breakdown: ScoreBreakdown;
  /** Which of the two paths decided the verdict. */
  decidedBy: 'hard-trigger' | 'known-bad-hash' | 'weighted-score';
}

export function decideVerdict(input: VerdictInput): VerdictOutcome {
  const { signals, rules, incompleteStages, knownBadHashMatch = false } = input;

  const breakdown = computeScore(signals, rules);
  const hardTriggers = evaluateHardTriggers(signals);
  const confidence = computeConfidence({ signals, incompleteStages });

  const scored = bucketForScore(breakdown.total);

  // A corpus hash match is the only route to KNOWN_MALICIOUS by assertion:
  // this exact artefact has already been confirmed bad.
  if (knownBadHashMatch) {
    return {
      verdict: 'KNOWN_MALICIOUS',
      confidence: CONFIDENCE_MAX,
      weightedScore: breakdown.total,
      hardTriggers,
      breakdown,
      decidedBy: 'known-bad-hash',
    };
  }

  if (hardTriggers.length > 0) {
    return {
      verdict: worstVerdict(scored, HARD_TRIGGER_MINIMUM_VERDICT),
      confidence,
      weightedScore: breakdown.total,
      hardTriggers,
      breakdown,
      decidedBy: verdictRank(scored) <= verdictRank(HARD_TRIGGER_MINIMUM_VERDICT)
        ? 'weighted-score'
        : 'hard-trigger',
    };
  }

  return {
    verdict: scored,
    confidence,
    weightedScore: breakdown.total,
    hardTriggers,
    breakdown,
    decidedBy: 'weighted-score',
  };
}
