import type { FormState } from '@/lib/form-state';

/**
 * Initial `useActionState` values and the state shapes that go with them.
 *
 * These live outside `actions.ts` deliberately. A `'use server'` module may only
 * export async functions: a constant exported from one is rewritten into a
 * server reference on the client, so `initialLoginState.step` arrived in the
 * browser as `undefined` and the sign-in form rendered its second step before
 * the first had ever been submitted. Plain values belong in a plain module.
 */

export interface LoginState extends FormState {
  /** Which step the form should render next. */
  step: 'password' | 'totp';
}

export const initialLoginState: LoginState = { status: 'idle', message: null, step: 'password' };

export interface RegisterState extends FormState {
  /** Set once registration succeeds so the page can show the "check your email" panel. */
  registeredEmail?: string;
  /** Non-production convenience link, mirroring the service's behaviour. */
  verificationToken?: string;
}

export const initialRegisterState: RegisterState = { status: 'idle', message: null };

export interface ForgotPasswordState extends FormState {
  resetToken?: string;
}

export const initialForgotPasswordState: ForgotPasswordState = { status: 'idle', message: null };

export interface PasswordScore {
  score: number;
  label: string;
  warning: string | null;
  suggestions: string[];
}
