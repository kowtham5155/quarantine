import type { ReactNode } from 'react';
import { AlertTriangle, CheckCircle2 } from 'lucide-react';

import type { FormState } from '@/lib/form-state';
import { cn } from '@/lib/utils';

/**
 * The two pieces of feedback every form in this application shows: a banner for
 * the action's own message and an inline message under a field.
 *
 * Both are `role="alert"` so a screen reader announces a failure that happened
 * without a navigation, which is the whole failure mode of a Server Action
 * form.
 */

export function FieldError({ state, field }: { state: FormState; field: string }) {
  const errors = state.fieldErrors?.[field];
  if (!errors || errors.length === 0) return null;

  return (
    <p id={`${field}-error`} role="alert" className="text-sm text-verdict-suspicious-accent">
      {errors[0]}
    </p>
  );
}

export interface FormBannerProps {
  state: FormState;
  /** Shown when the action succeeded. Omit for forms that navigate away. */
  successMessage?: ReactNode;
  className?: string;
}

export function FormBanner({ state, successMessage, className }: FormBannerProps) {
  if (state.status === 'error' && state.message) {
    return (
      <p
        role="alert"
        className={cn(
          'flex items-start gap-2 rounded-md border border-verdict-suspicious-accent/40 bg-verdict-suspicious-surface px-3 py-2 text-sm text-verdict-suspicious-accent',
          className,
        )}
      >
        <AlertTriangle aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
        <span>{state.message}</span>
      </p>
    );
  }

  if (state.status === 'success' && (successMessage || state.message)) {
    return (
      <p
        role="status"
        className={cn(
          'flex items-start gap-2 rounded-md border border-verdict-clean-accent/40 bg-verdict-clean-surface px-3 py-2 text-sm text-verdict-clean-accent',
          className,
        )}
      >
        <CheckCircle2 aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
        <span>{successMessage ?? state.message}</span>
      </p>
    );
  }

  return null;
}
