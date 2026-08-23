import { z } from 'zod';

/**
 * Environment contract, validated once at boot (CLAUDE.md — Zod at every input
 * boundary; process.env is the first one).
 *
 * A missing or malformed variable is a startup failure, not a runtime surprise
 * three requests later. `SKIP_ENV_VALIDATION=1` exists for build and CI steps
 * that compile the app without a database — it is never set in a running
 * deployment.
 */

const postgresUrl = z
  .string()
  .min(1, 'DATABASE_URL is required')
  .refine(
    (value) => value.startsWith('postgres://') || value.startsWith('postgresql://'),
    'DATABASE_URL must be a postgres:// or postgresql:// connection string',
  );

const httpUrl = z
  .string()
  .url('must be an absolute http(s) URL')
  .refine(
    (value) => value.startsWith('http://') || value.startsWith('https://'),
    'must be an absolute http(s) URL',
  );

export const envSchema = z.object({
  /** Neon Postgres connection string. */
  DATABASE_URL: postgresUrl,

  /** Auth.js signing secret. 32 bytes base64 (`openssl rand -base64 32`). */
  AUTH_SECRET: z.string().min(32, 'AUTH_SECRET must be at least 32 characters'),

  /** Canonical origin Auth.js issues callbacks against. */
  AUTH_URL: httpUrl,

  /** Public origin used to build absolute links in emails, reports and the CLI. */
  APP_URL: httpUrl,

  /** Shared secret the cron trigger presents on /api/cron/*. */
  CRON_SECRET: z.string().min(32, 'CRON_SECRET must be at least 32 characters'),

  /**
   * Optional GitHub token. Provenance diffing fetches repository tags and
   * tarballs; without a token the anonymous rate limit (60 req/h) makes
   * family 6 degrade to REPO_UNREACHABLE under any real load.
   */
  GITHUB_TOKEN: z.string().min(1).optional(),

  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),

  /** Optional log level override; defaults are set in lib/logger.ts. */
  LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).optional(),
});

export type Env = z.infer<typeof envSchema>;

function formatIssues(issues: z.ZodIssue[]): string {
  return issues
    .map((issue) => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`)
    .join('\n');
}

function parseEnv(): Env {
  if (process.env.SKIP_ENV_VALIDATION === '1' || process.env.SKIP_ENV_VALIDATION === 'true') {
    return process.env as unknown as Env;
  }

  const result = envSchema.safeParse(process.env);

  if (!result.success) {
    // Thrown before the server accepts a connection. Names only — never values.
    throw new Error(
      `Invalid environment configuration:\n${formatIssues(result.error.issues)}\n\n` +
        'See .env.example for the full contract.',
    );
  }

  return result.data;
}

export const env: Env = parseEnv();

export const isProduction = env.NODE_ENV === 'production';
export const isDevelopment = env.NODE_ENV === 'development';
export const isTest = env.NODE_ENV === 'test';
