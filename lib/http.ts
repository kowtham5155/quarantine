import { timingSafeEqual } from 'node:crypto';

import { env } from '@/lib/env';
import { AuthError, ForbiddenError, toAppError, toErrorResponse } from '@/lib/errors';
import { CORRELATION_ID_HEADER, logger } from '@/lib/logger';

/**
 * Shared plumbing for Route Handlers.
 *
 * Route Handlers exist for the four cases CLAUDE.md allows — webhooks, cron,
 * the CLI and the public API — plus the one streaming endpoint a Server Action
 * cannot express. They sit outside the Server Action pipeline, so the two
 * protections that pipeline provides for free (origin checking and uniform
 * error rendering) have to be applied explicitly here.
 */

// ---------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------

function allowedOrigins(): Set<string> {
  const origins = new Set<string>();
  for (const candidate of [env.APP_URL, env.AUTH_URL]) {
    try {
      origins.add(new URL(candidate).origin);
    } catch {
      // env.ts has already validated these as absolute URLs; a throw here would
      // only be reachable in a test that stubs the environment.
    }
  }
  return origins;
}

/**
 * Reject a cross-site state-changing request.
 *
 * Cookie-authenticated mutations need this: `SameSite=Lax` stops a cross-site
 * POST from carrying the session cookie in every browser that honours it, and
 * this is the server-side check that does not depend on that.
 *
 * The rule is deliberately strict — an absent `Origin` on a mutation is
 * rejected rather than assumed same-origin, because "the header is missing" is
 * exactly what a stripped-down attack client looks like. Every browser sends
 * `Origin` on POST. Non-browser callers authenticate with an API key on
 * `/api/v1`, which does not use cookies and does not come through here.
 */
export function requireSameOrigin(request: Request): void {
  const origin = request.headers.get('origin');

  if (!origin) {
    // Fetch metadata is the second opinion where it is available.
    const site = request.headers.get('sec-fetch-site');
    if (site === 'same-origin' || site === 'none') return;

    throw new ForbiddenError('This request could not be verified as coming from the app.');
  }

  if (!allowedOrigins().has(origin)) {
    logger.warn({ origin }, 'cross-origin mutation rejected');
    throw new ForbiddenError('This request could not be verified as coming from the app.');
  }
}

// ---------------------------------------------------------------------------
// Bearer secrets
// ---------------------------------------------------------------------------

/** Constant-time string comparison that does not leak length through timing. */
export function secretsMatch(presented: string, expected: string): boolean {
  const a = Buffer.from(presented, 'utf8');
  const b = Buffer.from(expected, 'utf8');

  // timingSafeEqual throws on a length mismatch, which would itself be a
  // timing oracle. Compare fixed-width digests of both instead.
  if (a.length !== b.length) {
    const padded = Buffer.alloc(Math.max(a.length, b.length));
    const other = Buffer.alloc(padded.length);
    a.copy(padded);
    b.copy(other);
    timingSafeEqual(padded, other);
    return false;
  }

  return timingSafeEqual(a, b);
}

/**
 * Authenticate a cron invocation.
 *
 * `/api/cron/*` is in the middleware's self-authenticating list, so this is the
 * only thing standing between the scheduler and an open endpoint that runs
 * analyses on demand.
 */
export function requireCronSecret(request: Request): void {
  const header = request.headers.get('authorization') ?? '';
  const presented = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : '';

  if (presented.length === 0 || !secretsMatch(presented, env.CRON_SECRET)) {
    logger.warn({ route: new URL(request.url).pathname }, 'cron request rejected');
    throw new AuthError('Invalid cron credentials.');
  }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

export function jsonResponse(
  body: unknown,
  init: { status?: number; headers?: Record<string, string> } = {},
): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      ...init.headers,
    },
  });
}

/**
 * Render any thrown value as the public error shape.
 *
 * Non-operational errors are logged with their cause and returned as a generic
 * 500: no stack trace, no driver message, no upstream body ever crosses the
 * boundary (CLAUDE.md rule 5).
 */
export function errorResponse(error: unknown, correlationId?: string): Response {
  const appError = toAppError(error);

  if (appError.isOperational) {
    logger.warn({ err: appError, correlationId }, 'request failed');
  } else {
    logger.error({ err: appError, correlationId }, 'unhandled request error');
  }

  const { status, body, headers } = toErrorResponse(appError);

  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...headers,
      'cache-control': 'no-store',
      ...(correlationId ? { [CORRELATION_ID_HEADER]: correlationId } : {}),
    },
  });
}
