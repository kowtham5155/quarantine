import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  DEFAULT_TOKEN_TTL_MS,
  hashToken,
  isExpired,
  issueToken,
  safeEqualHex,
  verifyToken,
} from '@/lib/tokens';

describe('issueToken', () => {
  it('returns a token, its digest, and an expiry one hour out by default', () => {
    const before = Date.now();
    const issued = issueToken();

    expect(issued.token.length).toBeGreaterThanOrEqual(40);
    expect(issued.tokenHash).toHaveLength(64);
    expect(issued.expiresAt.getTime()).toBeGreaterThanOrEqual(before + DEFAULT_TOKEN_TTL_MS - 50);
  });

  it('never repeats a token', () => {
    const tokens = new Set(Array.from({ length: 200 }, () => issueToken().token));
    expect(tokens.size).toBe(200);
  });

  it('stores only the digest — the plaintext is not recoverable from it', () => {
    const issued = issueToken();
    expect(issued.tokenHash).not.toContain(issued.token);
    expect(issued.tokenHash).toBe(createHash('sha256').update(issued.token).digest('hex'));
  });
});

describe('verifyToken', () => {
  it('accepts the matching token', () => {
    const issued = issueToken();
    expect(verifyToken(issued.token, issued.tokenHash)).toBe(true);
  });

  it('rejects a different token', () => {
    const a = issueToken();
    const b = issueToken();
    expect(verifyToken(b.token, a.tokenHash)).toBe(false);
  });

  it('rejects an empty token', () => {
    const issued = issueToken();
    expect(verifyToken('', issued.tokenHash)).toBe(false);
  });
});

describe('safeEqualHex', () => {
  it('is false for different lengths rather than throwing', () => {
    expect(safeEqualHex('abcd', 'abcdef')).toBe(false);
  });

  it('is true only for an exact match', () => {
    const digest = hashToken('hello');
    expect(safeEqualHex(digest, digest)).toBe(true);
    expect(safeEqualHex(digest, hashToken('hello '))).toBe(false);
  });
});

describe('isExpired', () => {
  it('treats the boundary as expired', () => {
    const now = new Date('2026-01-01T00:00:00.000Z');
    expect(isExpired(now, now)).toBe(true);
    expect(isExpired(new Date(now.getTime() + 1), now)).toBe(false);
    expect(isExpired(new Date(now.getTime() - 1), now)).toBe(true);
  });
});
