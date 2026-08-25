import { afterEach, describe, expect, it } from 'vitest';

import {
  MAINTAINER_RULES,
  analyseMaintainer,
  compareSemver,
  medianInterval,
  parseSemver,
} from '@/lib/engine/signals/maintainer';
import type { ReleaseRecord } from '@/lib/engine/types';

import { buildContext, cleanupFixtures, firedIds, maintainer, signalFor } from './fixture';

/**
 * FAMILY 5 — release forensics.
 *
 * SAFETY: this family reads publish timestamps and maintainer names. It never
 * opens a package file.
 *
 * The tests below care as much about what is *skipped* as about what fires.
 * npm does not publish account ages or maintainer-change history, and a rule
 * that quietly passes when it could not check is a rule that lies.
 */

afterEach(cleanupFixtures);

const DAY = 24 * 60 * 60 * 1000;

function release(version: string, iso: string): ReleaseRecord {
  return { version, publishedAt: new Date(iso) };
}

describe('analyseMaintainer', () => {
  it('evaluates every rule in the family', async () => {
    const context = await buildContext({
      version: '1.0.1',
      publishedAt: new Date('2026-02-01'),
      releaseHistory: [release('1.0.0', '2026-01-01'), release('1.0.1', '2026-02-01')],
    });
    const { signals } = await analyseMaintainer(context);

    expect(signals.map((signal) => signal.ruleId).sort()).toEqual([...MAINTAINER_RULES].sort());
    expect(signals.every((signal) => signal.family === 'MAINTAINER')).toBe(true);
  });

  it('skips the whole family when the registry gave no history at all', async () => {
    const context = await buildContext({ releaseHistory: [], publishedAt: new Date('2026-01-01') });
    const { signals } = await analyseMaintainer(context);

    expect(signals.every((signal) => signal.skipped === 'NO_METADATA')).toBe(true);
    expect(firedIds(signals).size).toBe(0);
  });

  it('skips the whole family when the version has no publish date', async () => {
    const context = await buildContext({
      publishedAt: null,
      releaseHistory: [release('1.0.0', '2026-01-01')],
    });
    const { signals } = await analyseMaintainer(context);

    expect(signals.every((signal) => signal.skipped === 'NO_METADATA')).toBe(true);
  });

  describe('Q-MNT-001 — dormancy break', () => {
    it('fires when a long-quiet package suddenly ships', async () => {
      const context = await buildContext({
        version: '1.0.1',
        publishedAt: new Date('2026-01-01'),
        releaseHistory: [release('1.0.0', '2025-01-01'), release('1.0.1', '2026-01-01')],
      });
      const { signals } = await analyseMaintainer(context);

      expect(firedIds(signals).has('Q-MNT-001')).toBe(true);
      expect(Number(signalFor(signals, 'Q-MNT-001').evidence[0]?.detail?.dormantDays)).toBe(365);
    });

    it('is more confident the longer the silence ran', async () => {
      const moderate = await buildContext({
        version: '1.0.1',
        publishedAt: new Date('2026-01-01'),
        releaseHistory: [release('1.0.0', '2025-01-01'), release('1.0.1', '2026-01-01')],
      });
      const severe = await buildContext({
        version: '1.0.1',
        publishedAt: new Date('2026-01-01'),
        releaseHistory: [release('1.0.0', '2024-01-01'), release('1.0.1', '2026-01-01')],
      });

      expect(
        signalFor((await analyseMaintainer(severe)).signals, 'Q-MNT-001').confidence,
      ).toBeGreaterThan(signalFor((await analyseMaintainer(moderate)).signals, 'Q-MNT-001').confidence);
    });

    it('does not fire on a package that releases regularly', async () => {
      const context = await buildContext({
        version: '1.0.1',
        publishedAt: new Date('2026-02-01'),
        releaseHistory: [release('1.0.0', '2026-01-01'), release('1.0.1', '2026-02-01')],
      });
      const { signals } = await analyseMaintainer(context);

      expect(firedIds(signals).has('Q-MNT-001')).toBe(false);
    });

    it('is not applicable to a first release, which has nothing to be dormant from', async () => {
      const context = await buildContext({
        version: '1.0.0',
        publishedAt: new Date('2026-01-01'),
        releaseHistory: [release('1.0.0', '2026-01-01')],
      });
      const { signals } = await analyseMaintainer(context);

      expect(signalFor(signals, 'Q-MNT-001').skipped).toBe('NOT_APPLICABLE');
    });
  });

  describe('Q-MNT-002 — a maintainer added just before the release', () => {
    it('skips rather than passing when the registry exposes no join dates', async () => {
      const context = await buildContext({
        version: '1.0.1',
        publishedAt: new Date('2026-02-01'),
        releaseHistory: [release('1.0.0', '2026-01-01'), release('1.0.1', '2026-02-01')],
        maintainers: [maintainer('alice')],
      });
      const { signals } = await analyseMaintainer(context);

      expect(signalFor(signals, 'Q-MNT-002').skipped).toBe('NO_METADATA');
    });

    it('fires when a maintainer joined inside the window', async () => {
      const publishedAt = new Date('2026-02-01');
      const context = await buildContext({
        version: '1.0.1',
        publishedAt,
        releaseHistory: [release('1.0.0', '2026-01-01'), release('1.0.1', '2026-02-01')],
        maintainers: [
          maintainer('founder', { firstSeenAt: new Date('2020-01-01') }),
          maintainer('newcomer', { firstSeenAt: new Date(publishedAt.getTime() - 10 * DAY) }),
        ],
      });
      const { signals } = await analyseMaintainer(context);

      expect(firedIds(signals).has('Q-MNT-002')).toBe(true);
      const evidence = signalFor(signals, 'Q-MNT-002').evidence;
      expect(evidence).toHaveLength(1);
      expect(evidence[0]?.detail?.maintainer).toBe('newcomer');
      expect(Number(evidence[0]?.detail?.daysBeforeRelease)).toBe(10);
    });

    it('does not fire on a long-standing maintainer', async () => {
      const context = await buildContext({
        version: '1.0.1',
        publishedAt: new Date('2026-02-01'),
        releaseHistory: [release('1.0.0', '2026-01-01'), release('1.0.1', '2026-02-01')],
        maintainers: [maintainer('founder', { firstSeenAt: new Date('2018-01-01') })],
      });
      const { signals } = await analyseMaintainer(context);

      expect(firedIds(signals).has('Q-MNT-002')).toBe(false);
    });
  });

  describe('Q-MNT-003 — a new or thin maintainer account', () => {
    it('skips when neither account age nor package count is available', async () => {
      const context = await buildContext({
        version: '1.0.1',
        publishedAt: new Date('2026-02-01'),
        releaseHistory: [release('1.0.0', '2026-01-01'), release('1.0.1', '2026-02-01')],
        maintainers: [maintainer('alice')],
      });
      const { signals } = await analyseMaintainer(context);

      expect(signalFor(signals, 'Q-MNT-003').skipped).toBe('NO_METADATA');
    });

    it('fires on an account created shortly before the release', async () => {
      const publishedAt = new Date('2026-02-01');
      const context = await buildContext({
        version: '1.0.1',
        publishedAt,
        releaseHistory: [release('1.0.0', '2026-01-01'), release('1.0.1', '2026-02-01')],
        maintainers: [
          maintainer('throwaway', { accountCreatedAt: new Date(publishedAt.getTime() - 30 * DAY) }),
        ],
      });
      const { signals } = await analyseMaintainer(context);

      expect(firedIds(signals).has('Q-MNT-003')).toBe(true);
    });

    it('fires on an account that maintains almost nothing else', async () => {
      const context = await buildContext({
        version: '1.0.1',
        publishedAt: new Date('2026-02-01'),
        releaseHistory: [release('1.0.0', '2026-01-01'), release('1.0.1', '2026-02-01')],
        maintainers: [maintainer('thin', { packageCount: 1 })],
      });
      const { signals } = await analyseMaintainer(context);

      expect(firedIds(signals).has('Q-MNT-003')).toBe(true);
    });

    it('does not fire on an established account', async () => {
      const context = await buildContext({
        version: '1.0.1',
        publishedAt: new Date('2026-02-01'),
        releaseHistory: [release('1.0.0', '2026-01-01'), release('1.0.1', '2026-02-01')],
        maintainers: [
          maintainer('veteran', { accountCreatedAt: new Date('2013-01-01'), packageCount: 200 }),
        ],
      });
      const { signals } = await analyseMaintainer(context);

      expect(firedIds(signals).has('Q-MNT-003')).toBe(false);
    });
  });

  describe('Q-MNT-004 — sole maintainer on a widely-installed package', () => {
    it('fires above the download floor', async () => {
      const context = await buildContext({
        version: '1.0.1',
        publishedAt: new Date('2026-02-01'),
        releaseHistory: [release('1.0.0', '2026-01-01'), release('1.0.1', '2026-02-01')],
        maintainers: [maintainer('solo')],
        weeklyDownloads: 5_000_000,
      });
      const { signals } = await analyseMaintainer(context);

      expect(firedIds(signals).has('Q-MNT-004')).toBe(true);
    });

    it('does not fire when the package has co-maintainers', async () => {
      const context = await buildContext({
        version: '1.0.1',
        publishedAt: new Date('2026-02-01'),
        releaseHistory: [release('1.0.0', '2026-01-01'), release('1.0.1', '2026-02-01')],
        maintainers: [maintainer('a'), maintainer('b')],
        weeklyDownloads: 5_000_000,
      });
      const { signals } = await analyseMaintainer(context);

      expect(firedIds(signals).has('Q-MNT-004')).toBe(false);
    });

    it('skips when the registry gave no download data', async () => {
      const context = await buildContext({
        version: '1.0.1',
        publishedAt: new Date('2026-02-01'),
        releaseHistory: [release('1.0.0', '2026-01-01'), release('1.0.1', '2026-02-01')],
        weeklyDownloads: null,
      });
      const { signals } = await analyseMaintainer(context);

      expect(signalFor(signals, 'Q-MNT-004').skipped).toBe('NO_DOWNLOAD_DATA');
    });
  });

  describe('Q-MNT-005 — anomalous version movement', () => {
    it('fires on a large major-version jump', async () => {
      const context = await buildContext({
        version: '9.0.0',
        publishedAt: new Date('2026-02-01'),
        releaseHistory: [release('1.2.3', '2026-01-01'), release('9.0.0', '2026-02-01')],
      });
      const { signals } = await analyseMaintainer(context);

      expect(firedIds(signals).has('Q-MNT-005')).toBe(true);
      expect(Number(signalFor(signals, 'Q-MNT-005').evidence[0]?.detail?.majorVersionsSkipped)).toBe(
        8,
      );
    });

    it('fires on a release published out of version order', async () => {
      const context = await buildContext({
        version: '1.9.9',
        publishedAt: new Date('2026-02-01'),
        releaseHistory: [release('2.0.0', '2026-01-01'), release('1.9.9', '2026-02-01')],
      });
      const { signals } = await analyseMaintainer(context);

      expect(firedIds(signals).has('Q-MNT-005')).toBe(true);
      expect(signalFor(signals, 'Q-MNT-005').evidence[0]?.detail?.note).toBe(
        'published out of version order',
      );
    });

    it('does not fire on an ordinary minor bump', async () => {
      const context = await buildContext({
        version: '1.1.0',
        publishedAt: new Date('2026-02-01'),
        releaseHistory: [release('1.0.0', '2026-01-01'), release('1.1.0', '2026-02-01')],
      });
      const { signals } = await analyseMaintainer(context);

      expect(firedIds(signals).has('Q-MNT-005')).toBe(false);
    });

    it('skips rather than guessing when the version is not semver', async () => {
      const context = await buildContext({
        version: 'nightly',
        publishedAt: new Date('2026-02-01'),
        releaseHistory: [release('1.0.0', '2026-01-01'), release('nightly', '2026-02-01')],
      });
      const { signals } = await analyseMaintainer(context);

      expect(signalFor(signals, 'Q-MNT-005').skipped).toBe('NO_METADATA');
    });
  });

  describe('Q-MNT-006 — cadence anomaly against the package\'s own history', () => {
    const steady: ReleaseRecord[] = [
      release('1.0.0', '2026-01-01'),
      release('1.0.1', '2026-01-11'),
      release('1.0.2', '2026-01-21'),
      release('1.0.3', '2026-01-31'),
      release('1.0.4', '2026-02-10'),
    ];

    it('fires when a release lands far outside the package\'s own rhythm', async () => {
      const context = await buildContext({
        version: '1.0.5',
        publishedAt: new Date('2026-08-29'),
        releaseHistory: [...steady, release('1.0.5', '2026-08-29')],
      });
      const { signals } = await analyseMaintainer(context);

      expect(firedIds(signals).has('Q-MNT-006')).toBe(true);
      expect(Number(signalFor(signals, 'Q-MNT-006').evidence[0]?.detail?.medianIntervalDays)).toBe(
        10,
      );
    });

    it('does not fire on a release that keeps the rhythm', async () => {
      const context = await buildContext({
        version: '1.0.5',
        publishedAt: new Date('2026-02-20'),
        releaseHistory: [...steady, release('1.0.5', '2026-02-20')],
      });
      const { signals } = await analyseMaintainer(context);

      expect(firedIds(signals).has('Q-MNT-006')).toBe(false);
    });

    it('skips when there are too few releases for a median to mean anything', async () => {
      const context = await buildContext({
        version: '1.0.1',
        publishedAt: new Date('2026-02-01'),
        releaseHistory: [release('1.0.0', '2026-01-01'), release('1.0.1', '2026-02-01')],
      });
      const { signals } = await analyseMaintainer(context);

      expect(signalFor(signals, 'Q-MNT-006').skipped).toBe('NO_METADATA');
    });
  });

  it('reproduces the event-stream shape: dormancy plus a new maintainer', async () => {
    const publishedAt = new Date('2026-01-01');
    const context = await buildContext({
      version: '3.3.6',
      publishedAt,
      releaseHistory: [release('3.3.5', '2025-01-01'), release('3.3.6', '2026-01-01')],
      maintainers: [
        maintainer('original', { firstSeenAt: new Date('2015-01-01') }),
        maintainer('right9ctrl', { firstSeenAt: new Date(publishedAt.getTime() - 21 * DAY) }),
      ],
    });
    const { signals } = await analyseMaintainer(context);
    const ids = firedIds(signals);

    expect(ids.has('Q-MNT-001')).toBe(true);
    expect(ids.has('Q-MNT-002')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

describe('parseSemver', () => {
  it('parses a plain version', () => {
    expect(parseSemver('1.2.3')).toEqual({ major: 1, minor: 2, patch: 3, prerelease: null });
  });

  it('tolerates a leading v and surrounding space', () => {
    expect(parseSemver('  v10.0.1 ')).toMatchObject({ major: 10, minor: 0, patch: 1 });
  });

  it('keeps the prerelease tag', () => {
    expect(parseSemver('2.0.0-beta.1')?.prerelease).toBe('beta.1');
  });

  it('returns null for anything that is not x.y.z', () => {
    expect(parseSemver('nightly')).toBeNull();
    expect(parseSemver('1.2')).toBeNull();
  });
});

describe('compareSemver', () => {
  const v = (value: string) => parseSemver(value)!;

  it('orders by major, then minor, then patch', () => {
    expect(compareSemver(v('2.0.0'), v('1.9.9'))).toBeGreaterThan(0);
    expect(compareSemver(v('1.2.0'), v('1.1.9'))).toBeGreaterThan(0);
    expect(compareSemver(v('1.1.2'), v('1.1.1'))).toBeGreaterThan(0);
  });

  it('sorts a prerelease below its own release', () => {
    expect(compareSemver(v('1.0.0-beta'), v('1.0.0'))).toBeLessThan(0);
  });

  it('calls identical versions equal', () => {
    expect(compareSemver(v('1.0.0'), v('1.0.0'))).toBe(0);
  });
});

describe('medianInterval', () => {
  it('is zero when there is nothing to measure', () => {
    expect(medianInterval([])).toBe(0);
    expect(medianInterval([release('1.0.0', '2026-01-01')])).toBe(0);
  });

  it('takes the middle gap for an odd number of gaps', () => {
    const history = [
      release('1.0.0', '2026-01-01'),
      release('1.0.1', '2026-01-02'),
      release('1.0.2', '2026-01-12'),
      release('1.0.3', '2026-02-11'),
    ];
    expect(medianInterval(history)).toBe(10 * DAY);
  });

  it('averages the middle two for an even number of gaps', () => {
    const history = [
      release('1.0.0', '2026-01-01'),
      release('1.0.1', '2026-01-03'),
      release('1.0.2', '2026-01-09'),
    ];
    expect(medianInterval(history)).toBe(4 * DAY);
  });
});
