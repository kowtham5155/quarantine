import { prisma } from '@/lib/db';
import { RateLimitError } from '@/lib/errors';
import { logger } from '@/lib/logger';

/**
 * Postgres-backed sliding-window rate limiter.
 *
 * No Redis: this deploys as a single Render web service against Neon, and
 * adding a second stateful dependency to enforce a limit that fires a few times
 * an hour is not a trade worth making. One row per counted attempt; the window
 * is evaluated by counting rows newer than `now - windowMs`, which is a true
 * sliding window rather than the fixed buckets a counter-per-interval gives you
 * (those let an attacker burst 2x the limit across a boundary).
 */

export interface RateLimitRule {
  /** Attempts permitted inside the window. */
  limit: number;
  windowMs: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  /** Seconds until the oldest attempt in the window ages out. */
  retryAfterSeconds: number;
  used: number;
}

const MINUTE = 60_000;

/** Named policies, so limits live in one place rather than at call sites. */
export const RATE_LIMITS = {
  /** 5 attempts per 15 minutes per IP+email, per the security baseline. */
  login: { limit: 5, windowMs: 15 * MINUTE },
  register: { limit: 5, windowMs: 60 * MINUTE },
  passwordReset: { limit: 5, windowMs: 60 * MINUTE },
  totpVerify: { limit: 10, windowMs: 15 * MINUTE },
  inviteSend: { limit: 30, windowMs: 60 * MINUTE },
  scanCreate: { limit: 60, windowMs: 60 * MINUTE },
  apiDefault: { limit: 300, windowMs: 60 * MINUTE },
} as const satisfies Record<string, RateLimitRule>;

export type RateLimitName = keyof typeof RATE_LIMITS;

/** Build a bucket key. Values are normalised so casing cannot split a bucket. */
export function bucketKey(
  name: RateLimitName,
  parts: Record<string, string | null | undefined>,
): string {
  const encoded = Object.entries(parts)
    .filter((entry): entry is [string, string] => Boolean(entry[1]))
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value.trim().toLowerCase()}`)
    .join('&');
  return `${name}:${encoded}`;
}

/**
 * Check a limit without recording an attempt. Use when you want to reject
 * before doing expensive work.
 */
export async function peek(name: RateLimitName, bucket: string): Promise<RateLimitResult> {
  const rule = RATE_LIMITS[name];
  const since = new Date(Date.now() - rule.windowMs);

  const used = await prisma.rateLimitEvent.count({
    where: { bucket, occurredAt: { gt: since } },
  });

  if (used < rule.limit) {
    return { allowed: true, remaining: rule.limit - used, retryAfterSeconds: 0, used };
  }

  const oldest = await prisma.rateLimitEvent.findFirst({
    where: { bucket, occurredAt: { gt: since } },
    orderBy: { occurredAt: 'asc' },
    select: { occurredAt: true },
  });

  const retryAfterMs = oldest
    ? Math.max(0, oldest.occurredAt.getTime() + rule.windowMs - Date.now())
    : rule.windowMs;

  return {
    allowed: false,
    remaining: 0,
    retryAfterSeconds: Math.ceil(retryAfterMs / 1000),
    used,
  };
}

/** Record one attempt against a bucket. */
export async function record(bucket: string): Promise<void> {
  await prisma.rateLimitEvent.create({ data: { bucket } });
}

/**
 * Record an attempt and return whether it was permitted.
 *
 * The attempt is recorded before the verdict is computed, so a burst of
 * concurrent requests cannot all read a stale count and slip through together.
 */
export async function consume(name: RateLimitName, bucket: string): Promise<RateLimitResult> {
  await record(bucket);
  const result = await peek(name, bucket);

  if (!result.allowed) {
    logger.warn({ bucket: name, used: result.used }, 'rate limit exceeded');
  }

  return result;
}

/** `consume`, but throws the error route handlers already render. */
export async function enforce(name: RateLimitName, bucket: string): Promise<void> {
  const result = await consume(name, bucket);
  if (!result.allowed) {
    throw new RateLimitError('Too many attempts. Try again shortly.', result.retryAfterSeconds);
  }
}

/** Drop a bucket's history, e.g. after a successful login. */
export async function reset(bucket: string): Promise<void> {
  await prisma.rateLimitEvent.deleteMany({ where: { bucket } });
}

/**
 * Exponential lockout applied on top of the sliding window.
 *
 * The window stops a burst; this stops a patient attacker who paces themselves
 * just under it. Doubling from one minute, capped at 24 hours.
 */
export function lockoutDurationMs(consecutiveFailures: number): number {
  if (consecutiveFailures < 5) return 0;
  // The exponent is bounded only to keep the doubling from overflowing; the
  // 24-hour ceiling below is what actually binds, and is reached at 16 failures.
  const exponent = Math.min(consecutiveFailures - 5, 32);
  return Math.min(MINUTE * 2 ** exponent, 24 * 60 * MINUTE);
}

/** Delete rows older than the longest window. Called from the cron sweep. */
export async function sweep(): Promise<number> {
  const longestWindowMs = Math.max(...Object.values(RATE_LIMITS).map((rule) => rule.windowMs));
  const { count } = await prisma.rateLimitEvent.deleteMany({
    where: { occurredAt: { lt: new Date(Date.now() - longestWindowMs * 2) } },
  });
  return count;
}
