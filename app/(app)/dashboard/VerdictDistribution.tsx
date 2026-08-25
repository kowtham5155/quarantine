'use client';

import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { VERDICT_META, type Verdict } from '@/lib/constants';

export interface VerdictDistributionProps {
  slices: Array<{ verdict: Verdict; count: number }>;
}

/**
 * Verdict distribution.
 *
 * Deliberately not a donut: five adjacent slices in the verdict ramp — three of
 * which are reds and oranges by design mandate — are separable by colour alone
 * for almost nobody. Horizontal bars carry the verdict badge (icon plus label)
 * and the count as text, so the colour is reinforcement rather than the channel.
 */
export function VerdictDistribution({ slices }: VerdictDistributionProps) {
  const total = slices.reduce((sum, slice) => sum + slice.count, 0);
  const max = slices.reduce((best, slice) => Math.max(best, slice.count), 0);

  if (total === 0) {
    return (
      <p className="py-6 text-center text-sm text-muted-foreground">
        No analysis has completed yet.
      </p>
    );
  }

  return (
    <ul className="space-y-3">
      {slices.map((slice) => {
        const share = total === 0 ? 0 : Math.round((slice.count / total) * 1000) / 10;
        const width =
          max === 0 ? 0 : Math.max(slice.count === 0 ? 0 : 2, (slice.count / max) * 100);

        return (
          <li key={slice.verdict} className="space-y-1.5">
            <div className="flex items-center justify-between gap-3">
              <VerdictBadge verdict={slice.verdict} size="sm" />
              <span className="font-mono text-xs text-muted-foreground tabular-nums">
                <span className="text-foreground">{slice.count}</span> · {share}%
              </span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
              <div
                className="h-full rounded-full"
                style={{ width: `${width}%`, backgroundColor: VERDICT_META[slice.verdict].hex }}
              />
            </div>
          </li>
        );
      })}
    </ul>
  );
}
