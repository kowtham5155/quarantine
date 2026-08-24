import 'server-only';

import { unstable_rethrow } from 'next/navigation';

import { RateLimitError, isAppError, type AppError } from '@/lib/errors';
import { GENERIC_FORM_ERROR, type FormState } from '@/lib/form-state';
import { logger } from '@/lib/logger';

/**
 * Server Actions must never hand a raw error to the client (CLAUDE.md rule 5),
 * so `toFormState` translates an AppError into its already-public message and
 * field errors, and collapses everything else into a single generic string.
 */

function fieldErrorsFrom(error: AppError): Record<string, string[]> | undefined {
  const details = error.details;
  if (!details) return undefined;

  const raw = details.fieldErrors;
  if (!raw || typeof raw !== 'object') return undefined;

  const out: Record<string, string[]> = {};
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    if (Array.isArray(value)) {
      out[key] = value.filter((item): item is string => typeof item === 'string');
    }
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/** Convert a thrown error into a FormState. Re-throws Next.js control flow. */
export function toFormState(error: unknown): FormState {
  // `redirect()` and `notFound()` work by throwing; swallowing them would break
  // navigation. `unstable_rethrow` re-throws exactly those and returns for
  // everything else.
  unstable_rethrow(error);

  if (isAppError(error)) {
    if (!error.isOperational) {
      logger.error({ err: error }, 'non-operational error in server action');
      return { status: 'error', message: GENERIC_FORM_ERROR };
    }

    const message =
      error instanceof RateLimitError
        ? `${error.message} (retry in ${error.retryAfterSeconds}s)`
        : error.message;

    const fieldErrors = fieldErrorsFrom(error);

    return {
      status: 'error',
      message,
      ...(fieldErrors ? { fieldErrors } : {}),
    };
  }

  logger.error({ err: error }, 'unhandled error in server action');
  return { status: 'error', message: GENERIC_FORM_ERROR };
}
