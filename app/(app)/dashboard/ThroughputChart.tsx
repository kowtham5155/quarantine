'use client';

import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { FLAGGED_SERIES_COLOR, SERIES_COLORS } from '@/lib/constants';

const COMPLETED = SERIES_COLORS[0];

export interface ThroughputChartProps {
  points: Array<{ date: string; completed: number; flagged: number }>;
}

interface TooltipPayloadItem {
  name?: string | number;
  value?: string | number;
  color?: string;
}

function shortDate(value: string): string {
  const parsed = new Date(`${value}T00:00:00Z`);
  return Number.isNaN(parsed.getTime())
    ? value
    : parsed.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', timeZone: 'UTC' });
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
      <p className="mb-1 font-medium text-foreground">{shortDate(String(label))}</p>
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
 * Analyses completed per day over the trailing fortnight, with the flagged
 * subset drawn on the same axis — they are the same unit, so one scale is the
 * only honest way to show them.
 */
export function ThroughputChart({ points }: ThroughputChartProps) {
  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={points} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
          <defs>
            <linearGradient id="completedFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={COMPLETED} stopOpacity={0.35} />
              <stop offset="100%" stopColor={COMPLETED} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--border)" strokeDasharray="2 4" vertical={false} />
          <XAxis
            dataKey="date"
            tickFormatter={shortDate}
            tick={{ fill: 'var(--muted-foreground)', fontSize: 11 }}
            tickLine={false}
            axisLine={{ stroke: 'var(--border)' }}
            minTickGap={24}
          />
          <YAxis
            allowDecimals={false}
            width={32}
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
            type="monotone"
            dataKey="completed"
            name="Completed"
            stroke={COMPLETED}
            strokeWidth={2}
            fill="url(#completedFill)"
            dot={false}
            activeDot={{ r: 4 }}
          />
          {/*
            Flagged is a line, not a second filled area. It is a subset of
            completed, so on a day where every analysis came back flagged the two
            curves coincide exactly — one fill drawn over another at that point
            hides the series underneath and reads as though flagged exceeded the
            total. A stroke on top of the fill stays legible either way.
          */}
          <Area
            type="monotone"
            dataKey="flagged"
            name="Flagged"
            stroke={FLAGGED_SERIES_COLOR}
            strokeWidth={2}
            fill="none"
            dot={false}
            activeDot={{ r: 4 }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
