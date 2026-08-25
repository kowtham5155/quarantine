'use client';

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { SIGNAL_FAMILY_META, SERIES_COLORS, type SignalFamily } from '@/lib/constants';
import type { FamilyMetric } from '@/lib/services/catalogue.service';

const PRECISION = SERIES_COLORS[0];
const RECALL = SERIES_COLORS[1];

interface Row {
  family: string;
  label: string;
  precision: number;
  recall: number;
}

function percent(value: number | null): number {
  return value === null ? 0 : Math.round(value * 1000) / 10;
}

interface TooltipPayloadItem {
  name?: string | number;
  value?: string | number;
  color?: string;
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
      <p className="mb-1 font-medium text-foreground">{label}</p>
      {payload.map((item) => (
        <p key={String(item.name)} className="flex items-center gap-2 text-muted-foreground">
          <span
            aria-hidden="true"
            className="size-2 rounded-full"
            style={{ backgroundColor: item.color }}
          />
          {item.name}
          <span className="ml-auto font-mono text-foreground tabular-nums">{item.value}%</span>
        </p>
      ))}
    </div>
  );
}

/**
 * Precision and recall per signal family.
 *
 * Two series, so a legend is always present and every bar carries its family
 * name on the axis — colour is never the only channel. One y-axis, fixed 0–100,
 * because two rates on different scales would be a lie about the comparison.
 */
export function FamilyMetricsChart({ metrics }: { metrics: FamilyMetric[] }) {
  const rows: Row[] = metrics.map((metric) => ({
    family: metric.family,
    label: SIGNAL_FAMILY_META[metric.family as SignalFamily].label,
    precision: percent(metric.precision),
    recall: percent(metric.recall),
  }));

  if (rows.length === 0) return null;

  return (
    <div className="h-80 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 8, left: 0 }} barGap={2}>
          <CartesianGrid stroke="var(--border)" strokeDasharray="2 4" vertical={false} />
          <XAxis
            dataKey="label"
            tick={{ fill: 'var(--muted-foreground)', fontSize: 11 }}
            tickLine={false}
            axisLine={{ stroke: 'var(--border)' }}
            interval={0}
            tickFormatter={(value: string) => value.split(' ')[0] ?? value}
          />
          <YAxis
            domain={[0, 100]}
            width={40}
            tick={{ fill: 'var(--muted-foreground)', fontSize: 11 }}
            tickLine={false}
            axisLine={false}
            unit="%"
          />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: 'var(--muted)', opacity: 0.3 }} />
          <Legend
            wrapperStyle={{ fontSize: 12, color: 'var(--muted-foreground)' }}
            iconType="circle"
            iconSize={8}
          />
          <Bar dataKey="precision" name="Precision" fill={PRECISION} radius={[4, 4, 0, 0]}>
            {rows.map((row) => (
              <Cell key={`p-${row.family}`} fill={PRECISION} />
            ))}
          </Bar>
          <Bar dataKey="recall" name="Recall" fill={RECALL} radius={[4, 4, 0, 0]}>
            {rows.map((row) => (
              <Cell key={`r-${row.family}`} fill={RECALL} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
