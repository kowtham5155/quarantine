import {
  COMBOSQUAT_AFFIXES,
  TYPOSQUAT_DOWNLOAD_SUPPRESSION_FLOOR,
  TYPOSQUAT_MAX_DISTANCE,
  TYPOSQUAT_MIN_NAME_LENGTH,
  TYPOSQUAT_PEER_DOWNLOAD_RATIO,
} from '@/lib/engine/thresholds';
import {
  POPULAR_PACKAGES,
  downloadsFor,
  isPopularPackage,
  popularNames,
} from '@/lib/engine/data/popular-packages';
import {
  canonicalName,
  damerauLevenshtein,
  foldConfusables,
  hasConfusableCharacters,
  hasNonAscii,
  looksLikeScopeConfusion,
  splitScope,
  stripSeparators,
} from '@/lib/engine/signals/distance';
import type { AnalysisContext, FamilyResult } from '@/lib/engine/types';
import { metadataEvidence, runFamily } from '@/lib/engine/signals/helpers';

/**
 * FAMILY 4 — identity.
 *
 * Whether this package is pretending to be a different, more popular one.
 *
 * ## The suppression rule is the important part
 *
 * Edit distance on its own produces an avalanche of false positives, because
 * ecosystems are full of legitimate sibling packages one edit apart:
 * `lodash.get` and `lodash.set`, `react-dom` and `react-dnd`, `chalk` and
 * `chalks`. Every one of them would be accused.
 *
 * Two suppressions keep this family usable, and they matter more than the
 * distance metric does:
 *
 *   1. A candidate that is itself popular is not a squat of anything. If the
 *      package has real install volume, it is a real package. This is
 *      TYPOSQUAT_DOWNLOAD_SUPPRESSION_FLOOR.
 *   2. A candidate with download volume comparable to its supposed target is a
 *      peer, not a parasite. A squat has a tiny fraction of its victim's
 *      traffic. This is TYPOSQUAT_PEER_DOWNLOAD_RATIO.
 *
 * The popular-package list ships as static data (`data/popular-packages.ts`)
 * and is never fetched at runtime.
 */

export const TYPOSQUAT_RULES = [
  'Q-TYP-001',
  'Q-TYP-002',
  'Q-TYP-003',
  'Q-TYP-004',
  'Q-TYP-005',
  'Q-TYP-006',
] as const;

export interface SquatCandidate {
  target: string;
  distance: number;
  technique: string;
  targetDownloads: number;
}

/**
 * Nearest popular packages within the distance budget.
 *
 * Exact matches are excluded: a package that *is* the popular package is not
 * squatting it. Comparison happens on the canonical form so that separator and
 * homoglyph tricks collapse onto their target rather than escaping via a larger
 * raw distance.
 */
export function findNearestTargets(name: string): SquatCandidate[] {
  const canonical = canonicalName(name);
  const results: SquatCandidate[] = [];

  for (const target of popularNames()) {
    if (target === name) continue;

    const targetCanonical = canonicalName(target);

    // Identical once separators and confusables are folded away: the strongest
    // form of impersonation, and distance 0 on the canonical form.
    if (targetCanonical === canonical) {
      results.push({
        target,
        distance: 0,
        technique: 'canonically identical',
        targetDownloads: downloadsFor(target),
      });
      continue;
    }

    if (canonical.length < TYPOSQUAT_MIN_NAME_LENGTH) continue;

    const distance = damerauLevenshtein(canonical, targetCanonical, TYPOSQUAT_MAX_DISTANCE);
    if (distance <= TYPOSQUAT_MAX_DISTANCE) {
      results.push({
        target,
        distance,
        technique: `edit distance ${distance}`,
        targetDownloads: downloadsFor(target),
      });
    }
  }

  // Closest first, then most popular: the most plausible victim leads.
  results.sort((a, b) => a.distance - b.distance || b.targetDownloads - a.targetDownloads);
  return results.slice(0, 5);
}

export interface SuppressionResult {
  suppressed: boolean;
  reason?: string;
}

/**
 * Group digits in threes, independent of the server's locale.
 *
 * `toLocaleString()` without an explicit locale follows the machine's setting,
 * so the same reason string renders as "12,93,52,221" on one host and
 * "1,293,52,221" on another. A report that reads differently depending on where
 * it ran is a report nobody can quote.
 */
function formatCount(value: number): string {
  return value.toLocaleString('en-US');
}

/** Whether identity findings should be suppressed for this package. */
export function shouldSuppress(
  name: string,
  candidateDownloads: number | null,
  targetDownloads: number,
): SuppressionResult {
  if (isPopularPackage(name)) {
    return { suppressed: true, reason: 'the package is itself on the popular list' };
  }

  if (candidateDownloads !== null) {
    if (candidateDownloads >= TYPOSQUAT_DOWNLOAD_SUPPRESSION_FLOOR) {
      return {
        suppressed: true,
        reason: `the package has ${formatCount(candidateDownloads)} weekly downloads of its own`,
      };
    }

    if (
      targetDownloads > 0 &&
      candidateDownloads / targetDownloads > TYPOSQUAT_PEER_DOWNLOAD_RATIO
    ) {
      return {
        suppressed: true,
        reason: 'download volume is comparable to the supposed target, so they read as peers',
      };
    }
  }

  return { suppressed: false };
}

export async function analyseTyposquat(context: AnalysisContext): Promise<FamilyResult> {
  return runFamily('TYPOSQUAT', context, TYPOSQUAT_RULES, async (builder) => {
    const { metadata } = context.artifact;
    const name = metadata.name;
    const downloads = metadata.weeklyDownloads;

    const fired = new Set<string>();
    const mark = (ruleId: string): void => void fired.add(ruleId);

    const nearest = findNearestTargets(name);
    const best = nearest[0];

    // -----------------------------------------------------------------------
    // Suppression, evaluated once and applied to every distance-based rule.
    //
    // Evaluated even when nothing is nearby: "this package is itself popular"
    // is a fact about the package, not about whether a target happened to be
    // found, and the report should say so either way.
    // -----------------------------------------------------------------------
    const suppression = shouldSuppress(name, downloads, best?.targetDownloads ?? 0);

    if (suppression.suppressed) {
      // Recorded as skipped rather than passed: the engine did not conclude the
      // name is fine, it concluded the question does not apply.
      for (const ruleId of ['Q-TYP-001', 'Q-TYP-003', 'Q-TYP-005'] as const) {
        builder.skip(ruleId, 'NOT_APPLICABLE');
      }
    }

    // -----------------------------------------------------------------------
    // Q-TYP-001 — edit distance from a popular package
    // -----------------------------------------------------------------------
    if (!suppression.suppressed && best && best.distance > 0) {
      mark('Q-TYP-001');
      builder.fire(
        'Q-TYP-001',
        best.distance === 1 ? 0.85 : 0.6,
        nearest
          .filter((candidate) => candidate.distance > 0)
          .map((candidate) =>
            metadataEvidence({
              target: candidate.target,
              distance: candidate.distance,
              targetWeeklyDownloads: candidate.targetDownloads,
              candidateWeeklyDownloads: downloads,
            }),
          ),
      );
    }

    // -----------------------------------------------------------------------
    // Q-TYP-002 — homoglyph substitution
    // -----------------------------------------------------------------------
    if (hasConfusableCharacters(name)) {
      const folded = foldConfusables(name);
      mark('Q-TYP-002');
      builder.fire('Q-TYP-002', 0.95, [
        metadataEvidence({
          rendered: name,
          foldsTo: folded,
          matchesPopular: isPopularPackage(folded),
        }),
      ]);
    } else if (hasNonAscii(name)) {
      // Non-ASCII that is not a known confusable is still worth noting: npm
      // normalises names, so a non-ASCII name reaching here is unusual.
      mark('Q-TYP-002');
      builder.fire('Q-TYP-002', 0.5, [
        metadataEvidence({
          rendered: name,
          note: 'non-ASCII characters in a package name',
        }),
      ]);
    }

    // -----------------------------------------------------------------------
    // Q-TYP-003 — separator manipulation
    // -----------------------------------------------------------------------
    if (!suppression.suppressed) {
      const stripped = stripSeparators(name.toLowerCase());
      for (const target of popularNames()) {
        if (target === name) continue;
        if (stripSeparators(target.toLowerCase()) !== stripped) continue;

        mark('Q-TYP-003');
        builder.fire('Q-TYP-003', 0.9, [
          metadataEvidence({
            target,
            technique: 'separators differ only',
            targetWeeklyDownloads: downloadsFor(target),
          }),
        ]);
        break;
      }
    }

    // -----------------------------------------------------------------------
    // Q-TYP-004 — scope confusion
    // -----------------------------------------------------------------------
    for (const target of popularNames()) {
      const confusion = looksLikeScopeConfusion(name, target);
      if (!confusion) continue;

      mark('Q-TYP-004');
      builder.fire('Q-TYP-004', 0.9, [
        metadataEvidence({
          target,
          technique: confusion.technique,
          targetWeeklyDownloads: downloadsFor(target),
        }),
      ]);
      break;
    }

    // -----------------------------------------------------------------------
    // Q-TYP-005 — combosquatting
    // -----------------------------------------------------------------------
    if (!suppression.suppressed) {
      const combo = findCombosquat(name);
      if (combo) {
        mark('Q-TYP-005');
        builder.fire('Q-TYP-005', 0.7, [
          metadataEvidence({
            target: combo.target,
            affix: combo.affix,
            position: combo.position,
            targetWeeklyDownloads: downloadsFor(combo.target),
          }),
        ]);
      }
    }

    // -----------------------------------------------------------------------
    // Q-TYP-006 — dependency-confusion posture
    // -----------------------------------------------------------------------
    // A package that looks like an internal name — scoped to something that is
    // not a known public scope, or named with an obvious internal prefix — and
    // is published publicly, is set up for a dependency-confusion attack.
    const posture = dependencyConfusionPosture(name, metadata.description);
    if (posture) {
      mark('Q-TYP-006');
      builder.fire('Q-TYP-006', 0.6, [
        metadataEvidence({ indicator: posture }),
      ]);
    }

    for (const ruleId of TYPOSQUAT_RULES) {
      if (!fired.has(ruleId)) builder.pass(ruleId);
    }
  });
}

export interface ComboMatch {
  target: string;
  affix: string;
  position: 'prefix' | 'suffix';
}

/** A popular name with a marketing affix bolted on: `react-official`, `js-lodash`. */
export function findCombosquat(name: string): ComboMatch | null {
  const canonical = canonicalName(name);

  for (const affix of COMBOSQUAT_AFFIXES) {
    for (const [position, stripped] of [
      ['suffix', trimEnd(canonical, affix)],
      ['prefix', trimStart(canonical, affix)],
    ] as const) {
      if (stripped === null) continue;
      if (stripped.length < TYPOSQUAT_MIN_NAME_LENGTH) continue;

      for (const target of popularNames()) {
        if (canonicalName(target) === stripped && target !== name) {
          return { target, affix, position };
        }
      }
    }
  }

  return null;
}

function trimEnd(value: string, affix: string): string | null {
  return value.endsWith(affix) ? value.slice(0, value.length - affix.length) : null;
}

function trimStart(value: string, affix: string): string | null {
  return value.startsWith(affix) ? value.slice(affix.length) : null;
}

/** Naming that suggests this was meant to be an internal, private package. */
export function dependencyConfusionPosture(name: string, description: string | null): string | null {
  const { scope } = splitScope(name);

  if (scope && /^(?:internal|private|corp|company|acme|test|dev|staging|local)/i.test(scope)) {
    return `scope "@${scope}" reads as an internal namespace`;
  }

  if (/^(?:internal|private|corp|company)[-_.]/i.test(name)) {
    return 'name begins with an internal-sounding prefix';
  }

  if (description && /\b(?:internal|private|do not (?:use|publish)|company[- ]only)\b/i.test(description)) {
    return 'description describes the package as internal';
  }

  return null;
}

export { POPULAR_PACKAGES };
