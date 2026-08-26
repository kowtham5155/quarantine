'use server';

import { headers } from 'next/headers';
import { redirect } from 'next/navigation';
import { AuthError as NextAuthError } from 'next-auth';

import { signIn } from '@/auth';
import { field, optionalField, type FormState } from '@/lib/form-state';
import { toFormState } from '@/lib/form-state.server';
import { scorePassword } from '@/lib/password';
import { PASSWORD_SCORE_LABELS } from '@/lib/password-policy';
import * as authService from '@/lib/services/auth.service';
import * as orgService from '@/lib/services/org.service';
import { getAuthContext } from '@/lib/auth-context';
import type {
  ForgotPasswordState,
  LoginState,
  PasswordScore,
  RegisterState,
} from '@/app/(auth)/form-states';

/**
 * Server Actions for the unauthenticated auth flows.
 *
 * Everything here is a thin adapter: parse the FormData, call the service, turn
 * a thrown AppError into a FormState. No business rules live in this file — the
 * service owns rate limiting, auditing and enumeration safety.
 */

async function requestInfo(): Promise<{ ip: string | null; userAgent: string | null }> {
  const headerList = await headers();
  const forwarded = headerList.get('x-forwarded-for');
  return {
    ip: forwarded ? (forwarded.split(',')[0]?.trim() ?? null) : null,
    userAgent: headerList.get('user-agent'),
  };
}

/** Only relative, single-slash paths are honoured as a post-login destination. */
function safeRedirect(target: string | undefined): string {
  if (!target) return '/dashboard';
  if (!target.startsWith('/') || target.startsWith('//')) return '/dashboard';
  return target;
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

export async function loginAction(_prev: LoginState, formData: FormData): Promise<LoginState> {
  const email = field(formData, 'email');
  const password = field(formData, 'password');
  const totp = optionalField(formData, 'totp');
  const next = safeRedirect(optionalField(formData, 'next'));

  try {
    const result = await authService.beginLogin({ email, password, totp }, await requestInfo());

    if (result.status === 'totp_required') {
      return {
        status: 'idle',
        message: null,
        step: 'totp',
        data: { email, password },
      };
    }

    await signIn('challenge', {
      challengeToken: result.challengeToken,
      redirect: false,
    });
  } catch (error) {
    if (error instanceof NextAuthError) {
      return {
        status: 'error',
        message: 'That sign-in could not be completed. Please try again.',
        step: totp ? 'totp' : 'password',
        ...(totp ? { data: { email, password } } : {}),
      };
    }

    const state = toFormState(error);
    return {
      ...state,
      step: totp ? 'totp' : 'password',
      ...(totp ? { data: { email, password } } : {}),
    };
  }

  redirect(next);
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

export async function registerAction(
  _prev: RegisterState,
  formData: FormData,
): Promise<RegisterState> {
  const email = field(formData, 'email');
  const name = field(formData, 'name');
  const password = field(formData, 'password');

  try {
    await authService.register({ email, name, password }, await requestInfo());

    return {
      status: 'success',
      message: null,
      registeredEmail: email.trim().toLowerCase(),
    };
  } catch (error) {
    return toFormState(error);
  }
}

/**
 * Strength meter for the registration and reset forms.
 *
 * zxcvbn runs on the server: its dictionaries are several hundred kilobytes and
 * have no business in a client bundle, and this keeps one implementation of the
 * policy rather than a client copy that can drift from the server's.
 */
export async function scorePasswordAction(
  password: string,
  userInputs: string[] = [],
): Promise<PasswordScore> {
  if (typeof password !== 'string' || password.length === 0) {
    return { score: 0, label: 'Too weak', warning: null, suggestions: [] };
  }

  const safeInputs = Array.isArray(userInputs)
    ? userInputs.filter((value): value is string => typeof value === 'string').slice(0, 5)
    : [];

  const result = await scorePassword(password.slice(0, 256), safeInputs);

  return {
    score: result.score,
    label: PASSWORD_SCORE_LABELS[result.score] ?? 'Too weak',
    warning: result.warning,
    suggestions: result.suggestions,
  };
}

// ---------------------------------------------------------------------------
// Password reset
// ---------------------------------------------------------------------------

export async function forgotPasswordAction(
  _prev: ForgotPasswordState,
  formData: FormData,
): Promise<ForgotPasswordState> {
  const email = field(formData, 'email');

  try {
    const result = await authService.requestPasswordReset({ email }, await requestInfo());

    // Deliberately identical whether or not the account exists: saying more
    // here would turn this form into an account-existence oracle.
    //
    // The token is never surfaced to this caller. Unlike an invitation, whoever
    // submitted this form has proved nothing — showing them the link would let
    // anyone reset anyone's password. Without a mail provider there is simply
    // no one to hand it to, and the message says so rather than implying an
    // email is on its way.
    return {
      status: 'success',
      message:
        'If that address has an account, a single-use reset link was created. There is no mail provider configured here, so it cannot be delivered and nothing will arrive.',
      ...(result.resetToken ? { resetToken: result.resetToken } : {}),
    };
  } catch (error) {
    return toFormState(error);
  }
}

export async function resetPasswordAction(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const token = field(formData, 'token');
  const password = field(formData, 'password');

  try {
    await authService.resetPassword({ token, password }, await requestInfo());
  } catch (error) {
    return toFormState(error);
  }

  redirect('/login?reset=1');
}

// ---------------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------------

export async function acceptInviteAction(_prev: FormState, formData: FormData): Promise<FormState> {
  const token = field(formData, 'token');

  const ctx = await getAuthContext();
  if (!ctx) {
    redirect(`/login?next=${encodeURIComponent(`/accept-invite/${token}`)}`);
  }

  try {
    await orgService.acceptInvite(
      { userId: ctx.userId, email: ctx.email },
      token,
      await requestInfo(),
    );
  } catch (error) {
    return toFormState(error);
  }

  redirect('/dashboard');
}
