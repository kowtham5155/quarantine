import { VerificationTokenType } from '@prisma/client';
import { z } from 'zod';

import { auditAnonymous, audit } from '@/lib/audit';
import { prisma } from '@/lib/db';
import { AuthError, NotFoundError, RateLimitError, ValidationError } from '@/lib/errors';
import { logger } from '@/lib/logger';
import { checkPasswordPolicy, hashPassword, verifyPassword } from '@/lib/password';
import { bucketKey, consume, lockoutDurationMs, reset as resetRateLimit } from '@/lib/rate-limit';
import type { AuthContext } from '@/lib/rbac';
import { hashToken, issueToken, isExpired, verifyToken } from '@/lib/tokens';
import {
  generateRecoveryCodes,
  generateTotpSecret,
  hashRecoveryCode,
  matchRecoveryCode,
  totpUri,
  verifyTotpCode,
} from '@/lib/totp';

/**
 * Authentication service.
 *
 * Two rules run through everything here:
 *
 * 1. **Enumeration safety.** Any endpoint an unauthenticated caller can reach
 *    with an arbitrary email returns the same response whether or not that
 *    email exists. Registration is the unavoidable exception — a unique
 *    constraint has to be reported somehow — and is handled by returning the
 *    same success response whether or not the address was taken.
 *
 * 2. **Every token is single-use, hashed at rest, and compared in constant
 *    time.** See lib/tokens.ts.
 */

export interface RequestInfo {
  ip?: string | null;
  userAgent?: string | null;
}

const emailSchema = z.string().trim().toLowerCase().email('Enter a valid email address.').max(254);

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

export const registerSchema = z.object({
  email: emailSchema,
  name: z.string().trim().min(1, 'Enter your name.').max(120),
  password: z.string().min(1, 'Enter a password.').max(256),
});

export type RegisterInput = z.infer<typeof registerSchema>;

export interface RegisterResult {
  /** Always true — the response does not reveal whether the email was taken. */
  ok: true;
}

export async function register(
  input: RegisterInput,
  request: RequestInfo = {},
): Promise<RegisterResult> {
  const parsed = registerSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const { email, name, password } = parsed.data;

  await enforceLimit('register', { ip: request.ip, email });

  const policy = await checkPasswordPolicy(password, [email, name]);
  if (!policy.ok) {
    throw new ValidationError('That password is not strong enough.', {
      details: { fieldErrors: { password: policy.problems } },
    });
  }

  const existing = await prisma.user.findUnique({ where: { email }, select: { id: true } });

  if (existing) {
    // Do not disclose that the account exists. A real deployment sends a
    // "someone tried to register with your address" mail here instead.
    logger.info({ email }, 'registration attempted for existing account');
    return { ok: true };
  }

  const passwordHash = await hashPassword(password);

  const user = await prisma.user.create({
    data: { email, name, passwordHash },
  });

  await auditAnonymous(
    { userId: user.id, email },
    'auth.registered',
    { type: 'User', id: user.id },
    { name },
    request,
  );

  return { ok: true };
}

// ---------------------------------------------------------------------------
// Login (step one — password, then TOTP)
// ---------------------------------------------------------------------------

export const beginLoginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, 'Enter your password.').max(256),
  /** Supplied on the second step when the account has TOTP enabled. */
  totp: z.string().trim().max(20).optional(),
});

export type BeginLoginInput = z.infer<typeof beginLoginSchema>;

export type BeginLoginResult =
  { status: 'totp_required' } | { status: 'ready'; challengeToken: string };

const GENERIC_LOGIN_FAILURE = 'That email and password combination is not valid.';

/**
 * Verify a password (and TOTP, when enabled) and issue a single-use login
 * challenge for the credentials provider to consume.
 *
 * Failure is always the same message and, as far as is practical, the same
 * amount of work: a missing account still pays for one argon2 verification
 * against a dummy hash so response time does not disclose existence.
 */
export async function beginLogin(
  input: BeginLoginInput,
  request: RequestInfo = {},
): Promise<BeginLoginResult> {
  const parsed = beginLoginSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const { email, password, totp } = parsed.data;

  await enforceLimit('login', { ip: request.ip, email });

  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    // Equalise timing against a known-cost hash.
    await verifyPassword(DUMMY_ARGON2_HASH, password);
    await recordLoginFailure(null, email, request, 'no_such_user');
    throw new AuthError(GENERIC_LOGIN_FAILURE);
  }

  if (user.lockedUntil && user.lockedUntil.getTime() > Date.now()) {
    const retryAfterSeconds = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 1000);
    await recordLoginFailure(user.id, email, request, 'locked');
    throw new RateLimitError(
      'This account is temporarily locked after repeated failed attempts.',
      retryAfterSeconds,
    );
  }

  const passwordOk = await verifyPassword(user.passwordHash, password);
  if (!passwordOk) {
    await recordLoginFailure(user.id, email, request, 'bad_password');
    throw new AuthError(GENERIC_LOGIN_FAILURE);
  }

  if (user.totpEnabled) {
    if (!totp) {
      return { status: 'totp_required' };
    }

    if (!user.totpSecret) {
      logger.error({ userId: user.id }, 'totpEnabled with no secret stored');
      throw new AuthError(GENERIC_LOGIN_FAILURE);
    }

    await enforceLimit('totpVerify', { ip: request.ip, email });

    // `afterTimeStep` rejects a code from a step already accepted, so a code
    // shoulder-surfed inside its 30-second window cannot be replayed.
    const result = await verifyTotpCode(user.totpSecret, totp, {
      afterTimeStep: user.lastTotpTimeStep,
    });

    if (result.valid) {
      await prisma.user.update({
        where: { id: user.id },
        data: { lastTotpTimeStep: result.timeStep },
      });
    } else {
      // Fall back to a recovery code. Each one is single-use: the matched
      // digest is removed before the login is allowed to proceed.
      const matched = matchRecoveryCode(totp, user.totpRecoveryCodes);
      if (!matched) {
        await recordLoginFailure(user.id, email, request, 'bad_totp');
        throw new AuthError('That verification code is not valid.');
      }

      const consumed = await prisma.user.updateMany({
        where: { id: user.id, totpRecoveryCodes: { has: matched } },
        data: { totpRecoveryCodes: user.totpRecoveryCodes.filter((h) => h !== matched) },
      });

      if (consumed.count === 0) {
        // Another request used the same code first.
        await recordLoginFailure(user.id, email, request, 'bad_totp');
        throw new AuthError('That verification code is not valid.');
      }

      await auditAnonymous(
        { userId: user.id, email },
        'auth.recovery_code_used',
        { type: 'User', id: user.id },
        { remaining: user.totpRecoveryCodes.length - 1 },
        request,
      );
    }
  }

  const challenge = issueToken(5 * 60 * 1000);

  await prisma.loginChallenge.create({
    data: {
      userId: user.id,
      tokenHash: challenge.tokenHash,
      totpRequired: false,
      ip: request.ip ?? null,
      userAgent: request.userAgent ?? null,
      expiresAt: challenge.expiresAt,
    },
  });

  await prisma.user.update({
    where: { id: user.id },
    data: { failedLoginCount: 0, lockedUntil: null },
  });

  await resetRateLimit(bucketKey('login', { ip: request.ip, email }));

  await auditAnonymous(
    { userId: user.id, email },
    'auth.login_succeeded',
    { type: 'User', id: user.id },
    { totpUsed: user.totpEnabled },
    request,
  );

  return { status: 'ready', challengeToken: challenge.token };
}

/**
 * A real argon2id digest of a value nobody knows, used to burn the same CPU on
 * a missing account as on a real one.
 */
const DUMMY_ARGON2_HASH =
  '$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZQ$JXqLQKmYQOxMhMxKX2bkTQxSMhwHhV0hHqCZ7yD7f0k';

async function recordLoginFailure(
  userId: string | null,
  email: string,
  request: RequestInfo,
  reason: string,
): Promise<void> {
  if (userId) {
    const updated = await prisma.user.update({
      where: { id: userId },
      data: { failedLoginCount: { increment: 1 } },
      select: { failedLoginCount: true },
    });

    const lockMs = lockoutDurationMs(updated.failedLoginCount);
    if (lockMs > 0) {
      await prisma.user.update({
        where: { id: userId },
        data: { lockedUntil: new Date(Date.now() + lockMs) },
      });
    }
  }

  await auditAnonymous(
    { userId, email },
    'auth.login_failed',
    { type: 'User', id: userId },
    { reason },
    request,
  );
}

async function enforceLimit(
  name: Parameters<typeof consume>[0],
  parts: Record<string, string | null | undefined>,
): Promise<void> {
  const bucket = bucketKey(name, parts);
  const result = await consume(name, bucket);
  if (!result.allowed) {
    throw new RateLimitError('Too many attempts. Try again shortly.', result.retryAfterSeconds);
  }
}

// ---------------------------------------------------------------------------
// Password reset
// ---------------------------------------------------------------------------

export const requestPasswordResetSchema = z.object({ email: emailSchema });

export interface RequestPasswordResetResult {
  /** Always true. The caller is told the same thing either way. */
  ok: true;
  resetToken?: string;
}

/** Enumeration-safe: identical response whether or not the account exists. */
export async function requestPasswordReset(
  input: z.infer<typeof requestPasswordResetSchema>,
  request: RequestInfo = {},
): Promise<RequestPasswordResetResult> {
  const parsed = requestPasswordResetSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const { email } = parsed.data;
  await enforceLimit('passwordReset', { ip: request.ip, email });

  const user = await prisma.user.findUnique({ where: { email }, select: { id: true } });
  if (!user) return { ok: true };

  // Invalidate any outstanding reset so only the newest link works.
  await prisma.verificationToken.deleteMany({
    where: { identifier: email, type: VerificationTokenType.PASSWORD_RESET },
  });

  const reset = issueToken();
  await prisma.verificationToken.create({
    data: {
      identifier: email,
      tokenHash: reset.tokenHash,
      type: VerificationTokenType.PASSWORD_RESET,
      expiresAt: reset.expiresAt,
    },
  });

  await auditAnonymous(
    { userId: user.id, email },
    'auth.password_reset_requested',
    { type: 'User', id: user.id },
    {},
    request,
  );

  return {
    ok: true,
    ...(process.env.NODE_ENV === 'production' ? {} : { resetToken: reset.token }),
  };
}

export const resetPasswordSchema = z.object({
  token: z.string().min(20).max(200),
  password: z.string().min(1, 'Enter a new password.').max(256),
});

/**
 * Complete a reset. Every other session for the user is revoked: if the reset
 * was triggered because the account was compromised, leaving the attacker's
 * session alive defeats the point.
 */
export async function resetPassword(
  input: z.infer<typeof resetPasswordSchema>,
  request: RequestInfo = {},
): Promise<{ ok: boolean }> {
  const parsed = resetPasswordSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const { token, password } = parsed.data;
  await enforceLimit('passwordReset', { ip: request.ip });

  const row = await prisma.verificationToken.findUnique({
    where: { tokenHash: hashToken(token) },
  });

  if (
    !row ||
    row.type !== VerificationTokenType.PASSWORD_RESET ||
    !verifyToken(token, row.tokenHash) ||
    isExpired(row.expiresAt)
  ) {
    throw new ValidationError('That reset link is invalid or has expired.');
  }

  const user = await prisma.user.findUnique({ where: { email: row.identifier } });
  if (!user) {
    await prisma.verificationToken.delete({ where: { id: row.id } });
    throw new ValidationError('That reset link is invalid or has expired.');
  }

  const policy = await checkPasswordPolicy(password, [user.email, user.name]);
  if (!policy.ok) {
    throw new ValidationError('That password is not strong enough.', {
      details: { fieldErrors: { password: policy.problems } },
    });
  }

  await prisma.user.update({
    where: { id: user.id },
    data: {
      passwordHash: await hashPassword(password),
      failedLoginCount: 0,
      lockedUntil: null,
      // A successful reset proves control of the mailbox.
      emailVerifiedAt: user.emailVerifiedAt ?? new Date(),
    },
  });

  await prisma.verificationToken.delete({ where: { id: row.id } });
  await prisma.session.updateMany({
    where: { userId: user.id, revokedAt: null },
    data: { revokedAt: new Date() },
  });
  await prisma.loginChallenge.deleteMany({ where: { userId: user.id, consumedAt: null } });

  await auditAnonymous(
    { userId: user.id, email: user.email },
    'auth.password_reset_completed',
    { type: 'User', id: user.id },
    { sessionsRevoked: true },
    request,
  );

  return { ok: true };
}

// ---------------------------------------------------------------------------
// Authenticated account management
// ---------------------------------------------------------------------------

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Enter your current password.').max(256),
  newPassword: z.string().min(1, 'Enter a new password.').max(256),
});

/** Change a password from inside a session. Other sessions are revoked. */
export async function changePassword(
  ctx: AuthContext & { actorEmail: string },
  input: z.infer<typeof changePasswordSchema>,
  request: RequestInfo = {},
): Promise<{ ok: boolean }> {
  const parsed = changePasswordSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const user = await prisma.user.findUnique({ where: { id: ctx.userId } });
  if (!user) throw new NotFoundError('Not found.');

  const currentOk = await verifyPassword(user.passwordHash, parsed.data.currentPassword);
  if (!currentOk) {
    throw new ValidationError('Your current password is not correct.', {
      details: { fieldErrors: { currentPassword: ['Your current password is not correct.'] } },
    });
  }

  const policy = await checkPasswordPolicy(parsed.data.newPassword, [user.email, user.name]);
  if (!policy.ok) {
    throw new ValidationError('That password is not strong enough.', {
      details: { fieldErrors: { newPassword: policy.problems } },
    });
  }

  await prisma.user.update({
    where: { id: user.id },
    data: { passwordHash: await hashPassword(parsed.data.newPassword) },
  });

  await prisma.session.updateMany({
    where: { userId: user.id, revokedAt: null },
    data: { revokedAt: new Date() },
  });

  await audit(ctx, 'auth.password_changed', { type: 'User', id: user.id }, {}, request);

  return { ok: true };
}

// ---------------------------------------------------------------------------
// TOTP enrolment
// ---------------------------------------------------------------------------

export interface TotpEnrolment {
  secret: string;
  uri: string;
}

/**
 * Begin enrolment. The secret is stored immediately but `totpEnabled` stays
 * false until a code proves the user has actually scanned it — otherwise a
 * mis-scan locks the account out of its own second factor.
 */
export async function enableTotp(
  ctx: AuthContext & { actorEmail: string },
): Promise<TotpEnrolment> {
  const user = await prisma.user.findUnique({ where: { id: ctx.userId } });
  if (!user) throw new NotFoundError('Not found.');

  if (user.totpEnabled) {
    throw new ValidationError('Two-factor authentication is already enabled.');
  }

  const secret = generateTotpSecret();
  await prisma.user.update({
    where: { id: user.id },
    data: { totpSecret: secret, totpEnabled: false },
  });

  return { secret, uri: totpUri(secret, user.email) };
}

export const verifyTotpSchema = z.object({
  code: z.string().trim().min(6, 'Enter the 6-digit code.').max(20),
});

export interface VerifyTotpResult {
  ok: boolean;
  /** Shown exactly once, immediately after enrolment. */
  recoveryCodes?: string[];
}

/** Confirm enrolment with a live code, then switch the second factor on. */
export async function verifyTotp(
  ctx: AuthContext & { actorEmail: string },
  input: z.infer<typeof verifyTotpSchema>,
  request: RequestInfo = {},
): Promise<VerifyTotpResult> {
  const parsed = verifyTotpSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  await enforceLimit('totpVerify', { userId: ctx.userId });

  const user = await prisma.user.findUnique({ where: { id: ctx.userId } });
  if (!user?.totpSecret) {
    throw new ValidationError('Start two-factor setup before entering a code.');
  }

  const result = await verifyTotpCode(user.totpSecret, parsed.data.code);
  if (!result.valid) {
    await audit(ctx, 'auth.totp_failed', { type: 'User', id: user.id }, {}, request);
    throw new ValidationError('That code is not valid. Check your device clock and try again.');
  }

  const recoveryCodes = generateRecoveryCodes();

  await prisma.user.update({
    where: { id: user.id },
    data: {
      totpEnabled: true,
      // Only digests are persisted; the plaintext list in the return value is
      // the one and only time the user will ever see it.
      totpRecoveryCodes: recoveryCodes.map(hashRecoveryCode),
      lastTotpTimeStep: result.timeStep,
    },
  });

  await audit(ctx, 'auth.totp_enabled', { type: 'User', id: user.id }, {}, request);

  return { ok: true, recoveryCodes };
}

export const disableTotpSchema = z.object({
  password: z.string().min(1, 'Confirm your password.').max(256),
});

/**
 * Turn the second factor off. A password is required: an attacker who walks up
 * to an unlocked laptop should not be able to strip the account's second factor
 * without knowing the first one.
 */
export async function disableTotp(
  ctx: AuthContext & { actorEmail: string },
  input: z.infer<typeof disableTotpSchema>,
  request: RequestInfo = {},
): Promise<{ ok: boolean }> {
  const parsed = disableTotpSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  await enforceLimit('totpVerify', { userId: ctx.userId });

  const user = await prisma.user.findUnique({ where: { id: ctx.userId } });
  if (!user) throw new NotFoundError('Not found.');

  const passwordOk = await verifyPassword(user.passwordHash, parsed.data.password);
  if (!passwordOk) {
    throw new ValidationError('That password is not correct.', {
      details: { fieldErrors: { password: ['That password is not correct.'] } },
    });
  }

  await prisma.user.update({
    where: { id: user.id },
    data: {
      totpEnabled: false,
      totpSecret: null,
      totpRecoveryCodes: [],
      lastTotpTimeStep: null,
    },
  });

  await audit(ctx, 'auth.totp_disabled', { type: 'User', id: user.id }, {}, request);

  return { ok: true };
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

export interface SessionSummary {
  id: string;
  ip: string | null;
  userAgent: string | null;
  createdAt: Date;
  expiresAt: Date;
  /** True for the session making the request, which the UI must not offer to kill silently. */
  current: boolean;
}

/** Live sessions for the calling user, newest first. */
export async function listSessions(
  ctx: AuthContext & { sessionId?: string },
): Promise<SessionSummary[]> {
  const rows = await prisma.session.findMany({
    where: { userId: ctx.userId, revokedAt: null, expiresAt: { gt: new Date() } },
    orderBy: { createdAt: 'desc' },
    select: { id: true, ip: true, userAgent: true, createdAt: true, expiresAt: true },
  });

  return rows.map((row) => ({ ...row, current: row.id === ctx.sessionId }));
}

/**
 * Revoke one session. Scoped by `userId` in the `where` clause so a guessed or
 * leaked session id belonging to somebody else simply matches nothing.
 */
export async function revokeSession(
  ctx: AuthContext & { actorEmail: string; sessionId?: string },
  sessionId: string,
  request: RequestInfo = {},
): Promise<{ ok: boolean }> {
  if (typeof sessionId !== 'string' || sessionId.length === 0 || sessionId.length > 64) {
    throw new ValidationError('Unknown session.');
  }

  const result = await prisma.session.updateMany({
    where: { id: sessionId, userId: ctx.userId, revokedAt: null },
    data: { revokedAt: new Date() },
  });

  if (result.count === 0) throw new NotFoundError('Unknown session.');

  await audit(
    ctx,
    'auth.session_revoked',
    { type: 'Session', id: sessionId },
    { self: sessionId === ctx.sessionId },
    request,
  );

  return { ok: true };
}

/** Revoke every session except the one making the request. */
export async function revokeOtherSessions(
  ctx: AuthContext & { actorEmail: string; sessionId: string },
  request: RequestInfo = {},
): Promise<{ ok: boolean; revoked: number }> {
  const result = await prisma.session.updateMany({
    where: { userId: ctx.userId, revokedAt: null, NOT: { id: ctx.sessionId } },
    data: { revokedAt: new Date() },
  });

  await audit(
    ctx,
    'auth.sessions_revoked_all',
    { type: 'User', id: ctx.userId },
    { revoked: result.count },
    request,
  );

  return { ok: true, revoked: result.count };
}
