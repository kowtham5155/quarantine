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

  /**
   * Optional unpooled connection string. Neon serves the default DATABASE_URL
   * through PgBouncer in transaction mode, which cannot run migrations; Prisma
   * uses this for `migrate` and `db push` only. Same credentials as
   * DATABASE_URL with `-pooler` removed from the host.
   */
  DIRECT_URL: postgresUrl.optional(),

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

  /**
   * Comma-separated emails allowed into /admin.
   *
   * Platform administration is deliberately not a role in the database. A role
   * can be granted through the application, and the whole point of this surface
   * is that it crosses tenant boundaries — so the only way in is a value an
   * operator sets on the deployment, which no request can change. Empty (the
   * default) means the surface is closed to everyone.
   */
  PLATFORM_ADMIN_EMAILS: z.string().optional(),

  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),

  /** Optional log level override; defaults are set in lib/logger.ts. */
  LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).optional(),
});

/** A Neon pooled endpoint, or anything else fronted by PgBouncer. */
function isPooled(url: string): boolean {
  return /-pooler\./.test(url) || /[?&]pgbouncer=true/.test(url);
}

/**
 * A pooled DATABASE_URL obliges a direct DIRECT_URL.
 *
 * Prisma does not error when `directUrl` resolves to nothing — it silently
 * falls back to `url`. Migrating through PgBouncer then appears to work while
 * leaving `pg_advisory_lock` held on a pooled backend that is handed straight
 * back to the app and never releases it. Every later `migrate deploy` fails
 * with P1002 against a lock nothing will ever free, and the message points at
 * the database rather than the missing variable that caused it.
 *
 * Failing at boot with the variable's name is worth far more than a deploy that
 * breaks an hour later for reasons that read like an outage.
 */
export const envSchemaChecked = envSchema.superRefine((value, ctx) => {
  if (!isPooled(value.DATABASE_URL)) return;

  if (!value.DIRECT_URL) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['DIRECT_URL'],
      message:
        'DATABASE_URL is a pooled (PgBouncer) endpoint, so DIRECT_URL is required — ' +
        'the same connection string with "-pooler" removed from the host. Without it ' +
        'Prisma migrates through the pooler and leaks the migration advisory lock.',
    });
    return;
  }

  if (isPooled(value.DIRECT_URL)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['DIRECT_URL'],
      message:
        'DIRECT_URL is also pooled. It must be the unpooled endpoint — the same ' +
        'connection string with "-pooler" removed from the host.',
    });
  }
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

  const result = envSchemaChecked.safeParse(process.env);

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

/** Normalised platform-admin allowlist. Lower-cased, empty entries dropped. */
export const platformAdminEmails: ReadonlySet<string> = new Set(
  (env.PLATFORM_ADMIN_EMAILS ?? '')
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => entry.length > 0),
);

export const isProduction = env.NODE_ENV === 'production';
export const isDevelopment = env.NODE_ENV === 'development';
export const isTest = env.NODE_ENV === 'test';
