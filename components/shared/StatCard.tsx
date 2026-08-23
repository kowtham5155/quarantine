import { ArrowDownRight, ArrowRight, ArrowUpRight, type LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';

import { Card, CardContent } from '@/components/ui/card';
import { cn } from '@/lib/utils';

export interface StatCardTrend {
  /** Signed percentage change over the comparison window. */
  changePercent: number;
  /** What the change is measured against, e.g. "vs. last 7 days". */
  label: string;
  /**
   * Whether an increase is good. Scan volume up is good; malicious findings up
   * is not — so direction alone cannot pick the colour.
   */
  increaseIsGood?: boolean;
}

export interface StatCardProps {
  label: string;
  value: string | number;
  /** Small qualifier under the value, e.g. "across 4 registries". */
  hint?: string;
  icon?: LucideIcon;
  trend?: StatCardTrend;
  /** Rendered in place of the value, for charts or sparklines. */
  children?: ReactNode;
  className?: string;
}

function TrendIndicator({ changePercent, label, increaseIsGood = true }: StatCardTrend) {
  const rounded = Math.round(changePercent * 10) / 10;
  const flat = rounded === 0;
  const up = rounded > 0;
  const good = flat ? null : up === increaseIsGood;

  const Icon = flat ? ArrowRight : up ? ArrowUpRight : ArrowDownRight;

  return (
    <p
      className={cn(
        'flex items-center gap-1 text-xs font-medium',
        good === null && 'text-muted-foreground',
        good === true && 'text-verdict-clean-accent',
        good === false && 'text-verdict-suspicious-accent',
      )}
    >
      <Icon aria-hidden="true" className="size-3.5" />
      <span className="font-mono tabular-nums">
        {up ? '+' : ''}
        {rounded}%
      </span>
      <span className="font-normal text-muted-foreground">{label}</span>
    </p>
  );
}

/** A single headline number on a dashboard, with optional trend context. */
export function StatCard({
  label,
  value,
  hint,
  icon: Icon,
  trend,
  children,
  className,
}: StatCardProps) {
  return (
    <Card className={cn('gap-0 py-4', className)}>
      <CardContent className="flex flex-col gap-2 px-4">
        <div className="flex items-center justify-between gap-2">
          <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
            {label}
          </p>
          {Icon ? <Icon aria-hidden="true" className="size-4 text-muted-foreground" /> : null}
        </div>

        {children ?? <p className="font-mono text-2xl font-semibold tabular-nums">{value}</p>}

        {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
        {trend ? <TrendIndicator {...trend} /> : null}
      </CardContent>
    </Card>
  );
}
