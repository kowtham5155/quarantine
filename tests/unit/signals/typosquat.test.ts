import { afterEach, describe, expect, it } from 'vitest';

import {
  POPULAR_PACKAGES,
  downloadsFor,
  isPopularPackage,
  popularNames,
} from '@/lib/engine/data/popular-packages';
import {
  TYPOSQUAT_DOWNLOAD_SUPPRESSION_FLOOR,
  TYPOSQUAT_MAX_DISTANCE,
} from '@/lib/engine/thresholds';
import {
  TYPOSQUAT_RULES,
  analyseTyposquat,
  dependencyConfusionPosture,
  findCombosquat,
  findNearestTargets,
  shouldSuppress,
} from '@/lib/engine/signals/typosquat';

import { buildContext, cleanupFixtures, firedIds, signalFor } from './fixture';

/**
 * FAMILY 4 — identity.
 *
 * The two assertions that matter are at the bottom: known squats resolve to
 * their real targets, and popular packages are never accused of squatting each
 * other. A typosquat family that fails the second one is worse than no family
 * at all, because every report becomes noise and the whole scanner gets muted.
 *
 * SAFETY: this family reads names and download counts. No package content is
 * involved at all.
 */

afterEach(cleanupFixtures);

/** Rules whose whole purpose is name similarity, and which suppression gates. */
const SIMILARITY_RULES = ['Q-TYP-001', 'Q-TYP-003', 'Q-TYP-005'] as const;

describe('findNearestTargets', () => {
  it('finds the intended victim of a one-edit squat', () => {
    expect(findNearestTargets('expres')[0]).toMatchObject({ target: 'express', distance: 1 });
  });

  it('collapses separator tricks onto the target at distance zero', () => {
    const nearest = findNearestTargets('crossenv');
    expect(nearest[0]).toMatchObject({ target: 'cross-env', distance: 0 });
  });

  it('never returns the package itself', () => {
    expect(findNearestTargets('lodash').every((candidate) => candidate.target !== 'lodash')).toBe(
      true,
    );
  });

  it('returns nothing for a name that resembles nothing popular', () => {
    expect(findNearestTargets('zqxjkvwmpb-internal-tool')).toEqual([]);
  });

  it('does not compare short names, where distance 2 relates everything', () => {
    // Four characters: at distance 2 a short name is "close" to half the
    // ecosystem, so the family declines to guess.
    expect(findNearestTargets('abcd').every((candidate) => candidate.distance === 0)).toBe(true);
  });

  it('stays within the distance budget', () => {
    for (const candidate of findNearestTargets('expres')) {
      expect(candidate.distance).toBeLessThanOrEqual(TYPOSQUAT_MAX_DISTANCE);
    }
  });

  it('leads with the closest, then the most popular victim', () => {
    const nearest = findNearestTargets('loadash');
    for (let index = 1; index < nearest.length; index++) {
      const previous = nearest[index - 1]!;
      const current = nearest[index]!;
      expect(previous.distance).toBeLessThanOrEqual(current.distance);
    }
  });
});

describe('shouldSuppress', () => {
  it('suppresses a package that is itself on the popular list', () => {
    const result = shouldSuppress('react-dom', 1_000_000, 5_000_000);
    expect(result.suppressed).toBe(true);
    expect(result.reason).toContain('popular list');
  });

  it('suppresses a package with real install volume of its own', () => {
    const result = shouldSuppress(
      'not-a-listed-package',
      TYPOSQUAT_DOWNLOAD_SUPPRESSION_FLOOR + 1,
      10_000_000,
    );
    expect(result.suppressed).toBe(true);
    expect(result.reason).toContain('weekly downloads');
  });

  it('suppresses a package whose volume is comparable to its supposed target', () => {
    const result = shouldSuppress('not-a-listed-package', 1_000, 5_000);
    expect(result.suppressed).toBe(true);
    expect(result.reason).toContain('peers');
  });

  it('does not suppress a package with a tiny fraction of its target traffic', () => {
    expect(shouldSuppress('not-a-listed-package', 50, 10_000_000).suppressed).toBe(false);
  });

  it('does not suppress when download data is missing entirely', () => {
    // No data is not evidence of innocence.
    expect(shouldSuppress('not-a-listed-package', null, 10_000_000).suppressed).toBe(false);
  });

  it('formats download counts independently of the machine locale', () => {
    const result = shouldSuppress('not-a-listed-package', 1_234_567, 10_000_000);
    expect(result.reason).toContain('1,234,567');
  });
});

describe('analyseTyposquat', () => {
  it('evaluates every rule in the family', async () => {
    const context = await buildContext({ name: 'a-completely-unrelated-name' });
    const { signals } = await analyseTyposquat(context);

    expect(signals.map((signal) => signal.ruleId).sort()).toEqual([...TYPOSQUAT_RULES].sort());
    expect(signals.every((signal) => signal.family === 'TYPOSQUAT')).toBe(true);
  });

  describe('Q-TYP-001 — edit distance', () => {
    it('fires on a one-edit squat of a popular name', async () => {
      const context = await buildContext({ name: 'expres' });
      const { signals } = await analyseTyposquat(context);

      expect(firedIds(signals).has('Q-TYP-001')).toBe(true);
      expect(signalFor(signals, 'Q-TYP-001').evidence[0]?.detail?.target).toBe('express');
    });

    it('is more confident at distance 1 than at distance 2', async () => {
      const near = await buildContext({ name: 'expres' });
      const far = await buildContext({ name: 'lodashh-x' });

      const nearConfidence = signalFor((await analyseTyposquat(near)).signals, 'Q-TYP-001')
        .confidence;
      const farSignal = signalFor((await analyseTyposquat(far)).signals, 'Q-TYP-001');

      if (farSignal.fired) expect(farSignal.confidence).toBeLessThan(nearConfidence);
      expect(nearConfidence).toBeGreaterThan(0.8);
    });

    it('is skipped, not passed, when suppression applies', async () => {
      const context = await buildContext({ name: 'react-dom', weeklyDownloads: 20_000_000 });
      const { signals } = await analyseTyposquat(context);

      for (const ruleId of SIMILARITY_RULES) {
        const signal = signalFor(signals, ruleId);
        expect(signal.fired).toBe(false);
        // The engine did not conclude the name is fine; it concluded the
        // question does not apply.
        expect(signal.skipped).toBe('NOT_APPLICABLE');
      }
    });
  });

  describe('Q-TYP-002 — homoglyphs', () => {
    it('fires on a Cyrillic lookalike and reports what it folds to', async () => {
      // "е" is Cyrillic small letter IE, indistinguishable from "e".
      const context = await buildContext({ name: 'exprеss' });
      const { signals } = await analyseTyposquat(context);

      const evidence = signalFor(signals, 'Q-TYP-002').evidence[0]?.detail;
      expect(firedIds(signals).has('Q-TYP-002')).toBe(true);
      expect(evidence?.foldsTo).toBe('express');
      expect(evidence?.matchesPopular).toBe(true);
    });

    it('fires with lower confidence on non-ASCII that is not a known confusable', async () => {
      const context = await buildContext({ name: 'pakkage-中文' });
      const { signals } = await analyseTyposquat(context);

      const signal = signalFor(signals, 'Q-TYP-002');
      expect(signal.fired).toBe(true);
      expect(signal.confidence).toBeLessThan(0.7);
    });

    it('does not fire on a plain ASCII name', async () => {
      const context = await buildContext({ name: 'a-completely-unrelated-name' });
      const { signals } = await analyseTyposquat(context);

      expect(firedIds(signals).has('Q-TYP-002')).toBe(false);
    });
  });

  describe('Q-TYP-003 — separator manipulation', () => {
    it('fires on a name that differs from a popular one only in separators', async () => {
      const context = await buildContext({ name: 'crossenv' });
      const { signals } = await analyseTyposquat(context);

      expect(firedIds(signals).has('Q-TYP-003')).toBe(true);
      expect(signalFor(signals, 'Q-TYP-003').evidence[0]?.detail?.target).toBe('cross-env');
    });
  });

  describe('Q-TYP-004 — scope confusion', () => {
    it('fires when a scope has been flattened into the name', async () => {
      const context = await buildContext({ name: 'babelcore' });
      const { signals } = await analyseTyposquat(context);

      expect(firedIds(signals).has('Q-TYP-004')).toBe(true);
      expect(signalFor(signals, 'Q-TYP-004').evidence[0]?.detail?.technique).toBe(
        'scope flattened into the name',
      );
    });

    it('fires when the scope itself is impersonated', async () => {
      const context = await buildContext({ name: '@babels/core' });
      const { signals } = await analyseTyposquat(context);

      expect(firedIds(signals).has('Q-TYP-004')).toBe(true);
      expect(signalFor(signals, 'Q-TYP-004').evidence[0]?.detail?.technique).toBe(
        'scope impersonated',
      );
    });
  });

  describe('Q-TYP-005 — combosquatting', () => {
    it('fires on a popular name with a marketing affix bolted on', async () => {
      const context = await buildContext({ name: 'lodash-js' });
      const { signals } = await analyseTyposquat(context);

      expect(firedIds(signals).has('Q-TYP-005')).toBe(true);
      expect(signalFor(signals, 'Q-TYP-005').evidence[0]?.detail?.target).toBe('lodash');
    });
  });

  describe('Q-TYP-006 — dependency-confusion posture', () => {
    it('fires on an internal-sounding scope published publicly', async () => {
      const context = await buildContext({ name: '@internalcorp/utils' });
      const { signals } = await analyseTyposquat(context);

      expect(firedIds(signals).has('Q-TYP-006')).toBe(true);
    });

    it('fires on a description that says the package is internal', async () => {
      const context = await buildContext({
        name: 'acme-shared-helpers',
        description: 'Internal helpers. Do not use outside the company.',
      });
      const { signals } = await analyseTyposquat(context);

      expect(firedIds(signals).has('Q-TYP-006')).toBe(true);
    });

    it('does not fire on an ordinary public package', async () => {
      const context = await buildContext({
        name: 'a-completely-unrelated-name',
        description: 'Does a thing.',
      });
      const { signals } = await analyseTyposquat(context);

      expect(firedIds(signals).has('Q-TYP-006')).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

describe('findCombosquat', () => {
  it('recognises an affix appended to a popular name', () => {
    expect(findCombosquat('lodash-js')).toMatchObject({ target: 'lodash', position: 'suffix' });
  });

  it('recognises an affix prepended to one', () => {
    expect(findCombosquat('node-lodash')).toMatchObject({ target: 'lodash', position: 'prefix' });
  });

  it('returns null when stripping the affix leaves nothing popular', () => {
    expect(findCombosquat('zqxjkvwmpb-cli')).toBeNull();
  });

  it('returns null when stripping leaves a name too short to judge', () => {
    expect(findCombosquat('ms-js')).toBeNull();
  });
});

describe('dependencyConfusionPosture', () => {
  it('recognises an internal-sounding scope', () => {
    expect(dependencyConfusionPosture('@internal-tools/logger', null)).toContain('internal');
  });

  it('recognises an internal-sounding name prefix', () => {
    expect(dependencyConfusionPosture('corp-logger', null)).not.toBeNull();
  });

  it('recognises a description that says so', () => {
    expect(dependencyConfusionPosture('logger', 'Private package, do not publish')).not.toBeNull();
  });

  it('returns null for an ordinary package', () => {
    expect(dependencyConfusionPosture('logger', 'A logger.')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The corpus assertion
// ---------------------------------------------------------------------------

describe('the typosquat corpus', () => {
  /**
   * Real squats from published incidents, with the package they impersonated.
   * Some resolve by edit distance and some by separator folding, which is why
   * the assertion is "an identity rule fired and named the target" rather than
   * "this specific rule fired".
   */
  const KNOWN_SQUATS: Array<{ name: string; target: string }> = [
    { name: 'expres', target: 'express' },
    { name: 'loadash', target: 'lodash' },
    { name: 'momnet', target: 'moment' },
    { name: 'crossenv', target: 'cross-env' },
    { name: 'axois', target: 'axios' },
    { name: 'event-strem', target: 'event-stream' },
    { name: 'babelcli', target: 'babel-cli' },
  ];

  it.each(KNOWN_SQUATS)('flags $name as impersonating $target', async ({ name, target }) => {
    const context = await buildContext({ name, weeklyDownloads: 40 });
    const { signals } = await analyseTyposquat(context);

    const identityHits = signals.filter(
      (signal) => signal.fired && SIMILARITY_RULES.includes(signal.ruleId as never),
    );
    expect(identityHits.length).toBeGreaterThan(0);

    const targets = identityHits.flatMap((signal) =>
      signal.evidence.map((record) => record.detail?.target),
    );
    expect(targets).toContain(target);
  });

  it('never accuses a package on the popular list of squatting', () => {
    // Cheap over the whole list: the suppression rule is what protects these,
    // and it is checked before any distance rule can fire.
    for (const [name] of POPULAR_PACKAGES) {
      const result = shouldSuppress(name, downloadsFor(name), Number.MAX_SAFE_INTEGER);
      expect(result.suppressed).toBe(true);
    }
  });

  it('fires no similarity rule when the top of the ecosystem is run end to end', async () => {
    // The expensive version of the same claim, over the packages most likely to
    // be each other's near neighbours — this is where `react-dom` beside
    // `react-dnd` would blow up if suppression were wrong.
    const top = popularNames().slice(0, 150);

    for (const name of top) {
      const context = await buildContext({ name, weeklyDownloads: downloadsFor(name) });
      const { signals } = await analyseTyposquat(context);

      for (const ruleId of SIMILARITY_RULES) {
        const signal = signalFor(signals, ruleId);
        if (signal.fired) {
          throw new Error(`${ruleId} fired on the popular package ${name}`);
        }
      }
    }
  }, 60_000);

  it('keeps the list itself internally consistent', () => {
    expect(POPULAR_PACKAGES.length).toBeGreaterThan(4000);
    for (const [name, downloads] of POPULAR_PACKAGES.slice(0, 200)) {
      expect(isPopularPackage(name)).toBe(true);
      expect(downloads).toBeGreaterThan(0);
    }
  });
});
