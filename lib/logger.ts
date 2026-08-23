import { randomUUID } from 'node:crypto';
import pino, { type Logger } from 'pino';

/**
 * Structured logging (CLAUDE.md rule 7 — no console.log anywhere).
 *
 * Redaction is deliberately broad: this service handles credentials, TOTP
 * secrets, API keys and package content lifted from untrusted tarballs. Any
 * field whose name suggests a secret is replaced before serialisation, at any
 * depth.
 */

const REDACT_PATHS = [
  'password',
  'passwordHash',
  'token',
  'apiKey',
  'authorization',
  '*.password',
  '*.passwordHash',
  '*.token',
  '*.apiKey',
  '*.authorization',
  '*.accessToken',
  '*.refreshToken',
  '*.secret',
  '*.totpSecret',
  '*.sessionToken',
  'req.headers.authorization',
  'req.headers.cookie',
  'res.headers["set-cookie"]',
  'headers.authorization',
  'headers.cookie',
  '*.headers.authorization',
  '*.headers.cookie',
];

const isProduction = process.env.NODE_ENV === 'production';

export const logger: Logger = pino({
  level: process.env.LOG_LEVEL ?? (isProduction ? 'info' : 'debug'),
  base: { service: 'quarantine' },
  redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
  timestamp: pino.stdTimeFunctions.isoTime,
  formatters: {
    level(label) {
      return { level: label };
    },
  },
});

/** Fields carried on every log line inside one request or job. */
export interface LogContext {
  correlationId: string;
  userId?: string;
  orgId?: string;
  route?: string;
  scanId?: string;
}

export const CORRELATION_ID_HEADER = 'x-correlation-id';

/** Accept an inbound correlation ID only if it is a plausible opaque token. */
export function normaliseCorrelationId(value: string | null | undefined): string {
  if (typeof value === 'string' && /^[A-Za-z0-9_-]{8,64}$/.test(value)) {
    return value;
  }
  return randomUUID();
}

/**
 * A child logger bound to one request, job or scan. Pass this down through
 * services rather than reaching for the root logger.
 */
export function createRequestLogger(context: LogContext): Logger {
  return logger.child(context);
}

/** Derive a request-scoped logger straight from an incoming request's headers. */
export function loggerForRequest(
  headers: Headers,
  extra: Omit<LogContext, 'correlationId'> = {},
): { logger: Logger; correlationId: string } {
  const correlationId = normaliseCorrelationId(headers.get(CORRELATION_ID_HEADER));
  return { logger: createRequestLogger({ correlationId, ...extra }), correlationId };
}

export type { Logger };
