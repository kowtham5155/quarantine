import {
  CADENCE_ANOMALY_MULTIPLE,
  CADENCE_MIN_RELEASES,
  DORMANCY_DAYS,
  DORMANCY_SEVERE_DAYS,
  MAINTAINER_ADDED_WINDOW_DAYS,
  MAINTAINER_FEW_PACKAGES,
  MAINTAINER_NEW_ACCOUNT_DAYS,
  SOLE_MAINTAINER_DOWNLOAD_FLOOR,
  VERSION_JUMP_MAJOR,
} from '@/lib/engine/thresholds';
import type { AnalysisContext, FamilyResult, ReleaseRecord } from '@/lib/engine/types';
import { metadataEvidence, runFamily } from '@/lib/engine/signals/helpers';

/**
 * FAMILY 5 — release forensics.
 *
 * The shape of a compromise, read from publish timestamps and maintainer lists
 * rather than from code. This is the family that would have caught event-stream
 * before anyone read the payload: a package dormant for months, a maintainer
 * added weeks earlier, then a sudden release.
 *
 * ## Honest about missing data
 *
 * npm's public registry API exposes publish timestamps and current maintainer
 * names. It does **not** expose account creation dates, per-account package
 * counts, or the history of when maintainers were added. Two of these six rules
 * depend on exactly that data.
 *
 * They report `NO_METADATA` rather than firing on a guess. A skipped rule is
 * visible in the report and feeds the incompleteness penalty, so the engine
 * says "I could not check this" instead of quietly claiming the package passed.
 */

export const MAINTAINER_RULES = [
  'Q-MNT-001',
  'Q-MNT-002',
  'Q-MNT-003',
  'Q-MNT-004',
  'Q-MNT-005',
  'Q-MNT-006',
] as const;

const DAY_MS = 24 * 60 * 60 * 1000;

export async function analyseMaintainer(context: AnalysisContext): Promise<FamilyResult> {
  return runFamily('MAINTAINER', context, MAINTAINER_RULES, async (builder) => {
    const { metadata } = context.artifact;
    const history = [...metadata.releaseHistory].sort(
      (a, b) => a.publishedAt.getTime() - b.publishedAt.getTime(),
    );

    const fired = new Set<string>();
    const mark = (ruleId: string): void => void fired.add(ruleId);

    if (history.length === 0 || !metadata.publishedAt) {
      for (const ruleId of MAINTAINER_RULES) builder.skip(ruleId, 'NO_METADATA');
      return;
    }

    const thisRelease = metadata.publishedAt;
    const index = history.findIndex((record) => record.version === metadata.version);
    const previous = index > 0 ? history[index - 1] : undefined;

    // -----------------------------------------------------------------------
    // Q-MNT-001 — dormancy break
    // -----------------------------------------------------------------------
    if (previous) {
      const gapDays = (thisRelease.getTime() - previous.publishedAt.getTime()) / DAY_MS;

      if (gapDays >= DORMANCY_DAYS) {
        mark('Q-MNT-001');
        builder.fire('Q-MNT-001', gapDays >= DORMANCY_SEVERE_DAYS ? 0.8 : 0.6, [
          metadataEvidence({
            previousVersion: previous.version,
            previousPublishedAt: previous.publishedAt.toISOString(),
            thisPublishedAt: thisRelease.toISOString(),
            dormantDays: Math.round(gapDays),
          }),
        ]);
      }
    } else if (index === 0) {
      // First release ever. Not dormancy — there is nothing to be dormant from.
      builder.skip('Q-MNT-001', 'NOT_APPLICABLE');
    }

    // -----------------------------------------------------------------------
    // Q-MNT-002 — maintainer added close to this release
    // -----------------------------------------------------------------------
    const withJoinDate = metadata.maintainers.filter((maintainer) => maintainer.firstSeenAt);

    if (withJoinDate.length === 0) {
      // The registry does not publish maintainer-change history. Say so.
      builder.skip('Q-MNT-002', 'NO_METADATA');
    } else {
      const recent = withJoinDate.filter((maintainer) => {
        const joined = maintainer.firstSeenAt;
        if (!joined) return false;
        const days = (thisRelease.getTime() - joined.getTime()) / DAY_MS;
        return days >= 0 && days <= MAINTAINER_ADDED_WINDOW_DAYS;
      });

      if (recent.length > 0) {
        mark('Q-MNT-002');
        builder.fire(
          'Q-MNT-002',
          0.85,
          recent.map((maintainer) =>
            metadataEvidence({
              maintainer: maintainer.name,
              firstSeenAt: maintainer.firstSeenAt?.toISOString() ?? null,
              daysBeforeRelease: Math.round(
                (thisRelease.getTime() - (maintainer.firstSeenAt?.getTime() ?? 0)) / DAY_MS,
              ),
            }),
          ),
        );
      }
    }

    // -----------------------------------------------------------------------
    // Q-MNT-003 — new or thin maintainer account
    // -----------------------------------------------------------------------
    const withAccountData = metadata.maintainers.filter(
      (maintainer) => maintainer.accountCreatedAt !== null || maintainer.packageCount !== null,
    );

    if (withAccountData.length === 0) {
      // npm does not expose account age or package counts publicly.
      builder.skip('Q-MNT-003', 'NO_METADATA');
    } else {
      const suspicious = withAccountData.filter((maintainer) => {
        const ageDays = maintainer.accountCreatedAt
          ? (thisRelease.getTime() - maintainer.accountCreatedAt.getTime()) / DAY_MS
          : Infinity;
        const thin =
          maintainer.packageCount !== null && maintainer.packageCount <= MAINTAINER_FEW_PACKAGES;
        return ageDays <= MAINTAINER_NEW_ACCOUNT_DAYS || thin;
      });

      if (suspicious.length > 0) {
        mark('Q-MNT-003');
        builder.fire(
          'Q-MNT-003',
          0.7,
          suspicious.map((maintainer) =>
            metadataEvidence({
              maintainer: maintainer.name,
              accountCreatedAt: maintainer.accountCreatedAt?.toISOString() ?? null,
              packageCount: maintainer.packageCount,
            }),
          ),
        );
      }
    }

    // -----------------------------------------------------------------------
    // Q-MNT-004 — sole maintainer on a widely-installed package
    // -----------------------------------------------------------------------
    // A bus-factor observation, not an accusation. Low weight by design: it
    // describes a risk the ecosystem carries, not evidence of an attack.
    if (metadata.weeklyDownloads === null) {
      builder.skip('Q-MNT-004', 'NO_DOWNLOAD_DATA');
    } else if (
      metadata.maintainers.length === 1 &&
      metadata.weeklyDownloads >= SOLE_MAINTAINER_DOWNLOAD_FLOOR
    ) {
      mark('Q-MNT-004');
      builder.fire('Q-MNT-004', 0.6, [
        metadataEvidence({
          maintainer: metadata.maintainers[0]?.name ?? 'unknown',
          weeklyDownloads: metadata.weeklyDownloads,
        }),
      ]);
    }

    // -----------------------------------------------------------------------
    // Q-MNT-005 — anomalous version jump
    // -----------------------------------------------------------------------
    if (previous) {
      const from = parseSemver(previous.version);
      const to = parseSemver(metadata.version);

      if (from && to) {
        const majorJump = to.major - from.major;

        if (majorJump >= VERSION_JUMP_MAJOR) {
          mark('Q-MNT-005');
          builder.fire('Q-MNT-005', 0.7, [
            metadataEvidence({
              from: previous.version,
              to: metadata.version,
              majorVersionsSkipped: majorJump,
            }),
          ]);
        } else if (compareSemver(to, from) < 0) {
          // A version lower than its predecessor: out-of-order publishing, which
          // is how a malicious release gets picked up by a loose range while
          // hiding below the latest tag.
          mark('Q-MNT-005');
          builder.fire('Q-MNT-005', 0.75, [
            metadataEvidence({
              from: previous.version,
              to: metadata.version,
              note: 'published out of version order',
            }),
          ]);
        }
      } else {
        builder.skip('Q-MNT-005', 'NO_METADATA');
      }
    }

    // -----------------------------------------------------------------------
    // Q-MNT-006 — cadence anomaly against the package's own history
    // -----------------------------------------------------------------------
    // Measured against the package itself rather than an absolute: a project
    // that ships daily and one that ships yearly are both normal, and only a
    // departure from their own rhythm is informative.
    if (history.length < CADENCE_MIN_RELEASES || !previous) {
      builder.skip('Q-MNT-006', 'NO_METADATA');
    } else {
      const median = medianInterval(history.slice(0, Math.max(1, index)));
      const gap = thisRelease.getTime() - previous.publishedAt.getTime();

      if (median > 0 && gap > median * CADENCE_ANOMALY_MULTIPLE) {
        mark('Q-MNT-006');
        builder.fire('Q-MNT-006', 0.55, [
          metadataEvidence({
            medianIntervalDays: Math.round(median / DAY_MS),
            thisIntervalDays: Math.round(gap / DAY_MS),
            multiple: Number((gap / median).toFixed(1)),
          }),
        ]);
      }
    }

    for (const ruleId of MAINTAINER_RULES) {
      if (!fired.has(ruleId)) builder.pass(ruleId);
    }
  });
}

export interface Semver {
  major: number;
  minor: number;
  patch: number;
  prerelease: string | null;
}

/** Permissive semver parse. Returns null for anything that is not `x.y.z`. */
export function parseSemver(version: string): Semver | null {
  const match = /^v?(\d+)\.(\d+)\.(\d+)(?:[-+](.+))?$/.exec(version.trim());
  if (!match) return null;

  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ?? null,
  };
}

/** Ordering by major, minor, patch. Prerelease sorts below its release. */
export function compareSemver(a: Semver, b: Semver): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;
  if (a.prerelease === b.prerelease) return 0;
  if (a.prerelease === null) return 1;
  if (b.prerelease === null) return -1;
  return a.prerelease < b.prerelease ? -1 : 1;
}

/** Median gap between consecutive releases, in milliseconds. */
export function medianInterval(history: ReleaseRecord[]): number {
  if (history.length < 2) return 0;

  const gaps: number[] = [];
  for (let index = 1; index < history.length; index++) {
    const current = history[index];
    const previous = history[index - 1];
    if (!current || !previous) continue;
    gaps.push(current.publishedAt.getTime() - previous.publishedAt.getTime());
  }

  if (gaps.length === 0) return 0;
  gaps.sort((a, b) => a - b);

  const middle = Math.floor(gaps.length / 2);
  if (gaps.length % 2 === 1) return gaps[middle] ?? 0;
  return ((gaps[middle - 1] ?? 0) + (gaps[middle] ?? 0)) / 2;
}
