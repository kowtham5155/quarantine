import { AlertTriangle, CheckCircle2, HelpCircle, ShieldAlert, ShieldX } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import { VERDICT_META, type Verdict } from '@/lib/constants';
import { cn } from '@/lib/utils';

const VERDICT_ICONS: Record<Verdict, LucideIcon> = {
  KNOWN_MALICIOUS: ShieldX,
  LIKELY_MALICIOUS: ShieldAlert,
  SUSPICIOUS: AlertTriangle,
  LOW_RISK: HelpCircle,
  CLEAN: CheckCircle2,
};

const SIZE_CLASSES = {
  sm: 'h-5 gap-1 px-2 text-[11px] [&_svg]:size-3',
  md: 'h-6 gap-1.5 px-2.5 text-xs [&_svg]:size-3.5',
  lg: 'h-8 gap-2 px-3.5 text-sm [&_svg]:size-4',
} as const;

export interface VerdictBadgeProps {
  verdict: Verdict;
  /** `solid` for the headline verdict, `subtle` for inline and table use. */
  appearance?: 'solid' | 'subtle';
  size?: keyof typeof SIZE_CLASSES;
  showIcon?: boolean;
  className?: string;
}

/**
 * The verdict scale, rendered consistently everywhere it appears. Colour is
 * never the only channel — the label and icon carry the same meaning, which is
 * what keeps this readable for colour-blind users (WCAG 1.4.1).
 */
export function VerdictBadge({
  verdict,
  appearance = 'subtle',
  size = 'md',
  showIcon = true,
  className,
}: VerdictBadgeProps) {
  const meta = VERDICT_META[verdict];
  const Icon = VERDICT_ICONS[verdict];

  return (
    <span
      data-verdict={verdict}
      className={cn(
        'inline-flex w-fit shrink-0 items-center rounded-full border font-medium whitespace-nowrap',
        SIZE_CLASSES[size],
        appearance === 'solid' ? `${meta.solidClass} border-transparent` : meta.subtleClass,
        className,
      )}
    >
      {showIcon ? <Icon aria-hidden="true" /> : null}
      {meta.label}
    </span>
  );
}
