/**
 * The AppError hierarchy (CLAUDE.md rule 5).
 *
 * Every error that crosses a service boundary is an AppError. Handlers render
 * `toPublicJSON()`, which is deliberately narrow: a stable machine code, a
 * message the author of the error explicitly marked as safe to show, and
 * optional structured details. Stack traces, driver messages and raw upstream
 * response bodies stay on the server, reachable only through `cause` and the
 * logger.
 */

export type ErrorCode =
  | 'VALIDATION_ERROR'
  | 'AUTH_ERROR'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'RATE_LIMITED'
  | 'EXTERNAL_SERVICE_ERROR'
  | 'ANALYSIS_ERROR'
  | 'INTERNAL_ERROR';

/** Shape returned to clients. Never contains anything host- or stack-derived. */
export interface PublicError {
  error: {
    code: ErrorCode;
    message: string;
    details?: Record<string, unknown>;
  };
}

export interface AppErrorOptions {
  /** Structured, already-sanitised context safe to return to the client. */
  details?: Record<string, unknown>;
  /** Original error. Logged, never serialised to a client. */
  cause?: unknown;
}

export abstract class AppError extends Error {
  abstract readonly code: ErrorCode;
  abstract readonly statusCode: number;

  /**
   * Operational errors are expected outcomes (bad input, missing row, upstream
   * 503). Non-operational errors indicate a bug and are alert-worthy.
   */
  readonly isOperational: boolean = true;

  readonly details: Record<string, unknown> | undefined;

  constructor(message: string, options: AppErrorOptions = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = new.target.name;
    this.details = options.details;
    Error.captureStackTrace?.(this, new.target);
  }

  /** Safe representation for a client response body. */
  toPublicJSON(): PublicError {
    return {
      error: {
        code: this.code,
        message: this.message,
        ...(this.details ? { details: this.details } : {}),
      },
    };
  }

  /** Full representation for the logger. Server-side only. */
  toLogJSON(): Record<string, unknown> {
    return {
      name: this.name,
      code: this.code,
      statusCode: this.statusCode,
      message: this.message,
      isOperational: this.isOperational,
      details: this.details,
      cause: this.cause instanceof Error ? this.cause.message : this.cause,
      stack: this.stack,
    };
  }
}

/** Input failed schema validation at a boundary. */
export class ValidationError extends AppError {
  readonly code = 'VALIDATION_ERROR' as const;
  readonly statusCode = 400;

  constructor(message = 'The submitted data is invalid.', options: AppErrorOptions = {}) {
    super(message, options);
  }

  /** Build from a Zod-style issue list without leaking the received values. */
  static fromIssues(
    issues: ReadonlyArray<{ path: ReadonlyArray<PropertyKey>; message: string }>,
    message = 'The submitted data is invalid.',
  ): ValidationError {
    const fieldErrors: Record<string, string[]> = {};
    for (const issue of issues) {
      const key = issue.path.length > 0 ? issue.path.map(String).join('.') : '_root';
      const bucket = fieldErrors[key];
      if (bucket) {
        bucket.push(issue.message);
      } else {
        fieldErrors[key] = [issue.message];
      }
    }
    return new ValidationError(message, { details: { fieldErrors } });
  }
}

/** Caller is unauthenticated, or their credentials/session are no longer valid. */
export class AuthError extends AppError {
  readonly code = 'AUTH_ERROR' as const;
  readonly statusCode = 401;

  constructor(message = 'Authentication is required.', options: AppErrorOptions = {}) {
    super(message, options);
  }
}

/** Caller is authenticated but lacks the role, or is reaching across a tenant boundary. */
export class ForbiddenError extends AppError {
  readonly code = 'FORBIDDEN' as const;
  readonly statusCode = 403;

  constructor(message = 'You do not have access to this resource.', options: AppErrorOptions = {}) {
    super(message, options);
  }
}

/**
 * Resource does not exist, or exists in another org. Both cases return the same
 * message on purpose — distinguishing them leaks cross-tenant existence.
 */
export class NotFoundError extends AppError {
  readonly code = 'NOT_FOUND' as const;
  readonly statusCode = 404;

  constructor(message = 'Not found.', options: AppErrorOptions = {}) {
    super(message, options);
  }
}

/** Caller exceeded a rate limit or lockout window. */
export class RateLimitError extends AppError {
  readonly code = 'RATE_LIMITED' as const;
  readonly statusCode = 429;

  /** Seconds until the caller may retry; surfaced as the Retry-After header. */
  readonly retryAfterSeconds: number;

  constructor(
    message = 'Too many requests. Try again shortly.',
    retryAfterSeconds = 60,
    options: AppErrorOptions = {},
  ) {
    super(message, {
      ...options,
      details: { ...options.details, retryAfterSeconds },
    });
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** An upstream dependency (npm registry, GitHub, OSV) failed or timed out. */
export class ExternalServiceError extends AppError {
  readonly code = 'EXTERNAL_SERVICE_ERROR' as const;
  readonly statusCode = 502;

  /** Which upstream failed. A short identifier, never a full URL with secrets. */
  readonly service: string;

  constructor(
    service: string,
    message = 'An upstream service is unavailable.',
    options: AppErrorOptions = {},
  ) {
    super(message, { ...options, details: { ...options.details, service } });
    this.service = service;
  }
}

/**
 * Static analysis could not complete: the tarball was malformed, exceeded an
 * extraction bound, or tripped a safety guard. Never means "malware found" —
 * that is a verdict, not an error.
 */
export class AnalysisError extends AppError {
  readonly code = 'ANALYSIS_ERROR' as const;
  readonly statusCode = 422;

  /** Machine-readable reason, e.g. `LIMIT_EXCEEDED`, `ZIP_SLIP`, `MALFORMED_ARCHIVE`. */
  readonly reason: string;

  constructor(
    reason: string,
    message = 'The package could not be analysed.',
    options: AppErrorOptions = {},
  ) {
    super(message, { ...options, details: { ...options.details, reason } });
    this.reason = reason;
  }
}

/** Fallback for anything unexpected. Its message is intentionally generic. */
export class InternalError extends AppError {
  readonly code = 'INTERNAL_ERROR' as const;
  readonly statusCode = 500;
  override readonly isOperational = false;

  constructor(message = 'Something went wrong.', options: AppErrorOptions = {}) {
    super(message, options);
  }
}

export function isAppError(error: unknown): error is AppError {
  return error instanceof AppError;
}

/**
 * Normalise anything thrown into an AppError. Unknown throwables become a
 * generic InternalError so no raw text ever reaches a client.
 */
export function toAppError(error: unknown): AppError {
  if (isAppError(error)) return error;
  return new InternalError('Something went wrong.', { cause: error });
}

/** Convenience for route handlers: the tuple needed to build a Response. */
export function toErrorResponse(error: unknown): {
  status: number;
  body: PublicError;
  headers: Record<string, string>;
} {
  const appError = toAppError(error);
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (appError instanceof RateLimitError) {
    headers['retry-after'] = String(appError.retryAfterSeconds);
  }
  return { status: appError.statusCode, body: appError.toPublicJSON(), headers };
}
