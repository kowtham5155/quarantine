import { describe, expect, it } from 'vitest';

import { RATE_LIMITS, bucketKey, lockoutDurationMs } from '@/lib/rate-limit';

const MINUTE = 60 * 1000;

describe('bucketKey', () => {
  it('is stable regardless of the order the parts are supplied in', () => {
    const a = bucketKey('login', { ip: '203.0.113.4', email: 'dev@example.com' });
    const b = bucketKey('login', { email: 'dev@example.com', ip: '203.0.113.4' });
    expect(a).toBe(b);
  });

  it('separates different subjects', () => {
    const a = bucketKey('login', { ip: '203.0.113.4', email: 'dev@example.com' });
    const b = bucketKey('login', { ip: '203.0.113.4', email: 'other@example.com' });
    expect(a).not.toBe(b);
  });

  it('separates the same subject across different limits', () => {
    const parts = { ip: '203.0.113.4', email: 'dev@example.com' };
    expect(bucketKey('login', parts)).not.toBe(bucketKey('passwordReset', parts));
  });

  it('ignores null and undefined parts rather than keying on the string "null"', () => {
    const withNull = bucketKey('login', { ip: null, email: 'dev@example.com' });
    const withUndefined = bucketKey('login', { ip: undefined, email: 'dev@example.com' });
    expect(withNull).toBe(withUndefined);
    expect(withNull).not.toContain('null');
  });
});

describe('login limit matches the security baseline', () => {
  it('is 5 attempts per 15 minutes', () => {
    expect(RATE_LIMITS.login.limit).toBe(5);
    expect(RATE_LIMITS.login.windowMs).toBe(15 * MINUTE);
  });
});

describe('lockoutDurationMs', () => {
  it('does not lock out before the fifth consecutive failure', () => {
    expect(lockoutDurationMs(0)).toBe(0);
    expect(lockoutDurationMs(4)).toBe(0);
  });

  it('starts at one minute and doubles', () => {
    expect(lockoutDurationMs(5)).toBe(MINUTE);
    expect(lockoutDurationMs(6)).toBe(2 * MINUTE);
    expect(lockoutDurationMs(7)).toBe(4 * MINUTE);
    expect(lockoutDurationMs(8)).toBe(8 * MINUTE);
  });

  it('caps at 24 hours however many failures accumulate', () => {
    // 2^11 minutes is the first doubling past a day, so 16 failures is where
    // the ceiling starts to bind.
    expect(lockoutDurationMs(16)).toBe(24 * 60 * MINUTE);
    expect(lockoutDurationMs(50)).toBe(24 * 60 * MINUTE);
    expect(lockoutDurationMs(5000)).toBe(24 * 60 * MINUTE);
  });

  it('is monotonic', () => {
    let previous = 0;
    for (let failures = 0; failures <= 40; failures++) {
      const current = lockoutDurationMs(failures);
      expect(current).toBeGreaterThanOrEqual(previous);
      previous = current;
    }
  });
});
