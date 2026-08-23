'use client';

import { useEffect, useState } from 'react';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

const RELATIVE = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
const ABSOLUTE = new Intl.DateTimeFormat('en-GB', {
  dateStyle: 'medium',
  timeStyle: 'short',
  timeZone: 'UTC',
});

function formatRelative(from: number, now: number): string {
  const diff = from - now;
  const abs = Math.abs(diff);

  if (abs < MINUTE) return 'just now';
  if (abs < HOUR) return RELATIVE.format(Math.round(diff / MINUTE), 'minute');
  if (abs < DAY) return RELATIVE.format(Math.round(diff / HOUR), 'hour');
  if (abs < 30 * DAY) return RELATIVE.format(Math.round(diff / DAY), 'day');
  if (abs < 365 * DAY) return RELATIVE.format(Math.round(diff / (30 * DAY)), 'month');
  return RELATIVE.format(Math.round(diff / (365 * DAY)), 'year');
}

export interface TimeAgoProps {
  date: Date | string | number;
  /** Refresh interval in ms. Set to 0 to render once and stop. */
  refreshMs?: number;
  className?: string;
}

/**
 * Relative timestamp with the absolute UTC value in the tooltip.
 *
 * The first render matches the server output exactly (the absolute string), and
 * the relative form is swapped in after mount — otherwise "3 minutes ago"
 * computed on the server and again on the client produces a hydration
 * mismatch.
 */
export function TimeAgo({ date, refreshMs = MINUTE, className }: TimeAgoProps) {
  const timestamp = new Date(date).getTime();
  const valid = Number.isFinite(timestamp);
  const [now, setNow] = useState<number | null>(null);

  useEffect(() => {
    if (!valid) return;
    setNow(Date.now());
    if (refreshMs <= 0) return;
    const id = setInterval(() => setNow(Date.now()), refreshMs);
    return () => clearInterval(id);
  }, [valid, refreshMs]);

  if (!valid) {
    return <span className={className}>—</span>;
  }

  const absolute = `${ABSOLUTE.format(timestamp)} UTC`;

  return (
    <time
      dateTime={new Date(timestamp).toISOString()}
      title={absolute}
      suppressHydrationWarning
      className={className}
    >
      {now === null ? absolute : formatRelative(timestamp, now)}
    </time>
  );
}
