'use client';

import {
  Area,
  CartesianGrid,
  ComposedChart,
  Legend,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { FLAGGED_SERIES_COLOR, SERIES_COLORS } from '@/lib/constants';

const TOTAL = SERIES_COLORS[0];
const HELD = SERIES_COLORS[1];

export interface RiskHistoryPoint {
  /** ISO instant the import finished. */
  at: string;
  total: number;
  flagged: number;
  blocked: number;
}

export interface RiskHistoryChartProps {
  points: RiskHistoryPoint[];
}

interface TooltipPayloadItem {
  name?: string | number;
  value?: string | number;
  color?: string;
}

function shortDate(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? value
    : parsed.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
}

function fullDate(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? value
    : parsed.toLocaleString('en-GB', {
        day: 'numeric',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
}

function ChartTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: TooltipPayloadItem[];
  label?: string | number;
}) {
  if (!active || !payload || payload.length === 0) return null;

  return (
    <div className="rounded-md border border-border bg-card px-3 py-2 text-xs shadow-md">
      <p className="mb-1 font-medium text-foreground">{fullDate(String(label))}</p>
      {payload.map((item) => (
        <p key={String(item.name)} className="flex items-center gap-2 text-muted-foreground">
          <span
            aria-hidden="true"
            className="size-2 rounded-full"
            style={{ backgroundColor: item.color }}
          />
          {item.name}
          <span className="ml-auto font-mono text-foreground tabular-nums">{item.value}</span>
        </p>
      ))}
    </div>
  );
}

/**
 * How the graph's size and risk moved as the lockfile changed.
 *
 * Stepped, not smoothed: a dependency count only changes at an import, and it
 * changes all at once. A monotone curve between two imports would draw counts
 * the project never actually had. Flagged and held are strokes on the same
 * axis — both are subsets of the total, and a second fill over the first hides
 * whichever series is underneath when they coincide.
 */
export function RiskHistoryChart({ points }: RiskHistoryChartProps) {
  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <ComposedChart data={points} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
          <defs>
            <linearGradient id="totalDepsFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={TOTAL} stopOpacity={0.3} />
              <stop offset="100%" stopColor={TOTAL} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--border)" strokeDasharray="2 4" vertical={false} />
          <XAxis
            dataKey="at"
            tickFormatter={shortDate}
            tick={{ fill: 'var(--muted-foreground)', fontSize: 11 }}
            tickLine={false}
            axisLine={{ stroke: 'var(--border)' }}
            minTickGap={24}
          />
          <YAxis
            allowDecimals={false}
            width={40}
            tick={{ fill: 'var(--muted-foreground)', fontSize: 11 }}
            tickLine={false}
            axisLine={false}
          />
          <Tooltip content={<ChartTooltip />} cursor={{ stroke: 'var(--border)' }} />
          <Legend
            wrapperStyle={{ fontSize: 12, color: 'var(--muted-foreground)' }}
            iconType="circle"
            iconSize={8}
          />
          <Area
            type="stepAfter"
            dataKey="total"
            name="Dependencies"
            stroke={TOTAL}
            strokeWidth={2}
            fill="url(#totalDepsFill)"
            dot={{ r: 2 }}
            activeDot={{ r: 4 }}
          />
          <Line
            type="stepAfter"
            dataKey="flagged"
            name="Flagged"
            stroke={FLAGGED_SERIES_COLOR}
            strokeWidth={2}
            dot={{ r: 2 }}
            activeDot={{ r: 4 }}
          />
          <Line
            type="stepAfter"
            dataKey="blocked"
            name="Held"
            stroke={HELD}
            strokeWidth={2}
            strokeDasharray="4 3"
            dot={{ r: 2 }}
            activeDot={{ r: 4 }}
          />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}
