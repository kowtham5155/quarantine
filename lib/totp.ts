import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { generateSecret, generateURI, verify } from 'otplib';

/**
 * TOTP second factor (RFC 6238).
 *
 * Verification allows one time step of drift in each direction — a 90 second
 * effective window. Wider than that and a shoulder-surfed code stays usable for
 * too long; narrower and users with a slightly wrong device clock cannot log in
 * at all.
 *
 * Replay is prevented by recording the matched time step: a code that has
 * already been accepted cannot be accepted again inside its own window.
 */

export const TOTP_ISSUER = 'Quarantine';
export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_DIGITS = 6;
/** One period either side. */
const EPOCH_TOLERANCE: [number, number] = [TOTP_PERIOD_SECONDS, TOTP_PERIOD_SECONDS];

export function generateTotpSecret(): string {
  return generateSecret({ length: 20 });
}

/** otpauth:// URI for an authenticator app QR code. */
export function totpUri(secret: string, accountLabel: string): string {
  return generateURI({
    strategy: 'totp',
    issuer: TOTP_ISSUER,
    label: accountLabel,
    secret,
    digits: TOTP_DIGITS,
    period: TOTP_PERIOD_SECONDS,
  });
}

export interface TotpVerification {
  valid: boolean;
  /** Time step the code matched, for replay protection. Null when invalid. */
  timeStep: number | null;
}

/** Normalise user input: strip spaces an authenticator app may display. */
export function normaliseTotpCode(input: string): string {
  return input.replace(/[\s-]/g, '');
}

export async function verifyTotpCode(
  secret: string,
  code: string,
  options: { afterTimeStep?: number | null } = {},
): Promise<TotpVerification> {
  const token = normaliseTotpCode(code);
  if (!/^\d{6}$/.test(token)) {
    return { valid: false, timeStep: null };
  }

  try {
    const result = await verify({
      strategy: 'totp',
      secret,
      token,
      digits: TOTP_DIGITS,
      period: TOTP_PERIOD_SECONDS,
      epochTolerance: EPOCH_TOLERANCE,
      // Rejects a code from a step at or before the last accepted one.
      ...(options.afterTimeStep != null ? { afterTimeStep: options.afterTimeStep } : {}),
    });

    if (!result.valid) return { valid: false, timeStep: null };

    // The return type unions the TOTP and HOTP shapes; only the TOTP one
    // carries a time step, so narrow before reading it.
    return {
      valid: true,
      timeStep: 'timeStep' in result ? result.timeStep : null,
    };
  } catch {
    // A malformed stored secret must read as "wrong code", not a 500.
    return { valid: false, timeStep: null };
  }
}

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

export const RECOVERY_CODE_COUNT = 10;

/** Human-transcribable: 10 characters, no ambiguous glyphs, grouped in fives. */
const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export function generateRecoveryCodes(count: number = RECOVERY_CODE_COUNT): string[] {
  const codes: string[] = [];
  for (let index = 0; index < count; index++) {
    const bytes = randomBytes(10);
    let code = '';
    for (const byte of bytes) {
      code += RECOVERY_ALPHABET[byte % RECOVERY_ALPHABET.length];
    }
    codes.push(`${code.slice(0, 5)}-${code.slice(5, 10)}`);
  }
  return codes;
}

export function hashRecoveryCode(code: string): string {
  return createHash('sha256').update(code.trim().toUpperCase()).digest('hex');
}

/** Constant-time match of a supplied code against a list of stored digests. */
export function matchRecoveryCode(code: string, storedHashes: string[]): string | null {
  const candidate = Buffer.from(hashRecoveryCode(code), 'utf8');
  let matched: string | null = null;

  // Every entry is compared, so timing does not reveal the position of a match.
  for (const stored of storedHashes) {
    const storedBuffer = Buffer.from(stored, 'utf8');
    if (storedBuffer.length === candidate.length && timingSafeEqual(storedBuffer, candidate)) {
      matched = stored;
    }
  }

  return matched;
}
