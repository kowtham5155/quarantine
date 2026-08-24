import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Single-use token discipline, shared by email verification, password reset and
 * invitations.
 *
 * The plaintext token is handed to the user once, inside a link, and never
 * stored. Only its SHA-256 is written to the database, so a database read does
 * not yield a usable token. Lookups compare digests with a timing-safe
 * comparison so response time does not leak how much of a token was correct.
 */

export const TOKEN_BYTES = 32;
export const DEFAULT_TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour

export interface IssuedToken {
  /** Give this to the user. Never persist it. */
  token: string;
  /** Persist this. */
  tokenHash: string;
  expiresAt: Date;
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function issueToken(ttlMs: number = DEFAULT_TOKEN_TTL_MS): IssuedToken {
  const token = randomBytes(TOKEN_BYTES).toString('base64url');
  return {
    token,
    tokenHash: hashToken(token),
    expiresAt: new Date(Date.now() + ttlMs),
  };
}

/**
 * Constant-time equality for two hex digests. Returns false rather than
 * throwing when lengths differ, since `timingSafeEqual` requires equal-length
 * buffers and a length mismatch is simply a non-match.
 */
export function safeEqualHex(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufferA = Buffer.from(a, 'utf8');
  const bufferB = Buffer.from(b, 'utf8');
  if (bufferA.length !== bufferB.length) return false;
  return timingSafeEqual(bufferA, bufferB);
}

/** True when a token matches a stored digest, compared in constant time. */
export function verifyToken(token: string, storedHash: string): boolean {
  return safeEqualHex(hashToken(token), storedHash);
}

export function isExpired(expiresAt: Date, now: Date = new Date()): boolean {
  return expiresAt.getTime() <= now.getTime();
}

/** A short opaque identifier for logs and correlation. Not a secret. */
export function shortId(): string {
  return randomBytes(8).toString('hex');
}
