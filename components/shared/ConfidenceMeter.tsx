import { cn } from '@/lib/utils';

export interface ConfidenceMeterProps {
  /** 0–1. Values outside the range are clamped. */
  value: number;
  label?: string;
  /** Hide the numeric readout and render the track alone. */
  hideValue?: boolean;
  size?: 'sm' | 'md';
  className?: string;
}

function bandFor(percent: number): { label: string; barClass: string; textClass: string } {
  if (percent >= 80) {
    return { label: 'High', barClass: 'bg-verdict-clean', textClass: 'text-verdict-clean-accent' };
  }
  if (percent >= 55) {
    return {
      label: 'Moderate',
      barClass: 'bg-verdict-low-risk',
      textClass: 'text-verdict-low-risk-accent',
    };
  }
  return {
    label: 'Low',
    barClass: 'bg-verdict-suspicious',
    textClass: 'text-verdict-suspicious-accent',
  };
}

/**
 * Analysis confidence — how much of the package the engine actually got to
 * inspect, and how well the fired signals corroborate each other. Distinct from
 * the verdict: a CLEAN verdict at 40% confidence is a very different statement
 * from CLEAN at 95%.
 */
export function ConfidenceMeter({
  value,
  label = 'Confidence',
  hideValue = false,
  size = 'md',
  className,
}: ConfidenceMeterProps) {
  const percent = Math.round(Math.min(1, Math.max(0, Number.isFinite(value) ? value : 0)) * 100);
  const band = bandFor(percent);

  return (
    <div className={cn('flex w-full flex-col gap-1.5', className)}>
      {hideValue ? null : (
        <div className="flex items-baseline justify-between gap-2">
          <span className="text-xs font-medium text-muted-foreground">{label}</span>
          <span className={cn('font-mono text-xs font-semibold tabular-nums', band.textClass)}>
            {percent}% <span className="font-sans text-muted-foreground">· {band.label}</span>
          </span>
        </div>
      )}
      <div
        role="meter"
        aria-valuenow={percent}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`${label}: ${percent} percent, ${band.label}`}
        className={cn(
          'w-full overflow-hidden rounded-full bg-muted',
          size === 'sm' ? 'h-1' : 'h-1.5',
        )}
      >
        <div
          className={cn('h-full rounded-full transition-[width] duration-500', band.barClass)}
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  );
}
