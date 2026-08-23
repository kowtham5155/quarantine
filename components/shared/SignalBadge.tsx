import { SIGNAL_FAMILY_META, type SignalFamily } from '@/lib/constants';
import { cn } from '@/lib/utils';

export interface SignalBadgeProps {
  family: SignalFamily;
  /** Rule ID such as `Q-INS-002`. Rendered monospace next to the family name. */
  ruleId?: string;
  /** Hide the family label and show only the rule ID plus a colour dot. */
  compact?: boolean;
  className?: string;
}

/** A signal family, optionally carrying the specific rule that fired. */
export function SignalBadge({ family, ruleId, compact = false, className }: SignalBadgeProps) {
  const meta = SIGNAL_FAMILY_META[family];

  return (
    <span
      data-signal-family={family}
      title={meta.description}
      className={cn(
        'inline-flex w-fit shrink-0 items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap',
        meta.subtleClass,
        className,
      )}
    >
      <span aria-hidden="true" className={cn('size-1.5 shrink-0 rounded-full', meta.dotClass)} />
      {compact ? null : meta.label}
      {ruleId ? <code className="font-mono text-[11px] opacity-80">{ruleId}</code> : null}
    </span>
  );
}
