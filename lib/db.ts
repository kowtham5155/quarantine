import { Prisma, PrismaClient } from '@prisma/client';

import { env, isProduction } from '@/lib/env';
import { logger } from '@/lib/logger';

/**
 * Prisma singleton.
 *
 * Next's dev server re-evaluates modules on every hot reload. Without stashing
 * the client on globalThis, each reload opens a new connection pool and Neon
 * starts refusing connections within a few minutes of editing.
 *
 * Importing this module also pulls in lib/env, so a misconfigured environment
 * fails at boot rather than on the first query.
 */

const globalForPrisma = globalThis as unknown as {
  quarantinePrisma?: PrismaClient;
};

function createPrismaClient(): PrismaClient {
  const client = new PrismaClient({
    datasources: { db: { url: env.DATABASE_URL } },
    log: isProduction
      ? [
          { emit: 'event', level: 'warn' },
          { emit: 'event', level: 'error' },
        ]
      : [
          { emit: 'event', level: 'query' },
          { emit: 'event', level: 'warn' },
          { emit: 'event', level: 'error' },
        ],
  });

  // Query text is parameterised, so it is safe to log; params are not, and are
  // deliberately never included.
  client.$on('query' as never, (event: Prisma.QueryEvent) => {
    logger.debug({ durationMs: event.duration, query: event.query }, 'prisma query');
  });

  client.$on('warn' as never, (event: Prisma.LogEvent) => {
    logger.warn({ target: event.target }, event.message);
  });

  client.$on('error' as never, (event: Prisma.LogEvent) => {
    logger.error({ target: event.target }, event.message);
  });

  return client;
}

export const prisma: PrismaClient = globalForPrisma.quarantinePrisma ?? createPrismaClient();

if (!isProduction) {
  globalForPrisma.quarantinePrisma = prisma;
}

export { Prisma };
export type { PrismaClient };
