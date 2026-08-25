import type { FormState } from '@/lib/form-state';

/**
 * Initial `useActionState` values for onboarding.
 *
 * Kept out of `actions.ts` for the same reason as the auth form states: a
 * `'use server'` module may only export async functions, and a constant
 * exported from one becomes a server reference in the browser rather than the
 * object the form expects.
 */

export interface InviteState extends FormState {
  /** Invitations sent so far in this wizard, newest last. */
  sent?: string[];
  /** Non-production accept links, so the flow is testable without email. */
  links?: Record<string, string>;
}

export const initialInviteState: InviteState = { status: 'idle', message: null };
