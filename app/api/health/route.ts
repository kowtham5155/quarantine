import { prisma } from '@/lib/db';
import { jsonResponse } from '@/lib/http';
import { ENGINE_VERSION } from '@/lib/services/analysis.service';
import { logger } from '@/lib/logger';

/**
 * GET /api/health — is this instance able to serve requests?
 *
 * Unauthenticated on purpose: it is the platform's health check and the target
 * of the ten-minute warm ping that keeps a free-tier instance from sleeping.
 * That means it must give away nothing. No connection string, no driver
 * message, no stack: a failing database is reported as the single word
 * `unreachable`, and the real cause goes to the log with a correlation id.
 *
 * The check is one round trip. A health endpoint that does real work becomes
 * the thing that takes the instance down when it is already struggling.
 */

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

/** Reported so a deploy can be confirmed without reading the dashboard. */
const startedAt = Date.now();

export async function GET(): Promise<Response> {
  const began = Date.now();

  let database: 'ok' | 'unreachable' = 'ok';
  let latencyMs: number | null = null;

  try {
    // Parameterised tagged template, never $queryRawUnsafe.
    await prisma.$queryRaw`SELECT 1`;
    latencyMs = Date.now() - began;
  } catch (error) {
    database = 'unreachable';
    logger.error({ err: error }, 'health check: database unreachable');
  }

  const healthy = database === 'ok';

  return jsonResponse(
    {
      status: healthy ? 'ok' : 'degraded',
      engineVersion: ENGINE_VERSION,
      uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
      checks: { database, databaseLatencyMs: latencyMs },
    },
    {
      status: healthy ? 200 : 503,
      // A cached health check answers for the instance it was cached from.
      headers: { 'cache-control': 'no-store, max-age=0' },
    },
  );
}
