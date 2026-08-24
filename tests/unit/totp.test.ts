import { describe, expect, it } from 'vitest';

import {
  RECOVERY_CODE_COUNT,
  TOTP_DIGITS,
  TOTP_ISSUER,
  TOTP_PERIOD_SECONDS,
  generateRecoveryCodes,
  generateTotpSecret,
  hashRecoveryCode,
  matchRecoveryCode,
  normaliseTotpCode,
  totpUri,
  verifyTotpCode,
} from '@/lib/totp';

describe('generateTotpSecret', () => {
  it('produces a base32 secret an authenticator app can accept', () => {
    const secret = generateTotpSecret();
    expect(secret).toMatch(/^[A-Z2-7]+$/);
    expect(secret.length).toBeGreaterThanOrEqual(16);
  });

  it('never repeats', () => {
    const secrets = new Set(Array.from({ length: 100 }, () => generateTotpSecret()));
    expect(secrets.size).toBe(100);
  });
});

describe('totpUri', () => {
  it('carries the issuer, the label and the secret', () => {
    const uri = totpUri('JBSWY3DPEHPK3PXP', 'dev@example.com');
    const parsed = new URL(uri);

    expect(parsed.protocol).toBe('otpauth:');
    expect(parsed.searchParams.get('issuer')).toBe(TOTP_ISSUER);
    expect(parsed.searchParams.get('secret')).toBe('JBSWY3DPEHPK3PXP');
    expect(decodeURIComponent(parsed.pathname)).toContain('dev@example.com');
  });

  it('omits digits and period because both are the otpauth defaults', () => {
    // Emitting them anyway is legal but noisier, and every authenticator app
    // assumes 6/30 when they are absent. Guard the assumption instead.
    expect(TOTP_DIGITS).toBe(6);
    expect(TOTP_PERIOD_SECONDS).toBe(30);

    const uri = totpUri('JBSWY3DPEHPK3PXP', 'dev@example.com');
    expect(uri).not.toContain('digits=');
    expect(uri).not.toContain('period=');
  });

  it('escapes an account label containing a colon or a space', () => {
    const uri = totpUri('JBSWY3DPEHPK3PXP', 'first last:weird@example.com');
    expect(() => new URL(uri)).not.toThrow();
    expect(uri).not.toContain(' ');
  });
});

describe('normaliseTotpCode', () => {
  it('strips the spacing an authenticator app displays', () => {
    expect(normaliseTotpCode('123 456')).toBe('123456');
    expect(normaliseTotpCode('123-456')).toBe('123456');
  });
});

describe('verifyTotpCode', () => {
  it('rejects anything that is not six digits without touching the secret', async () => {
    for (const bad of ['', 'abcdef', '12345', '1234567', '12 34 5']) {
      const result = await verifyTotpCode('JBSWY3DPEHPK3PXP', bad);
      expect(result.valid).toBe(false);
      expect(result.timeStep).toBeNull();
    }
  });

  it('reads a malformed stored secret as a wrong code, not an exception', async () => {
    await expect(verifyTotpCode('not-a-base32-secret!!', '123456')).resolves.toEqual({
      valid: false,
      timeStep: null,
    });
  });

  it('rejects a plainly wrong code against a real secret', async () => {
    const result = await verifyTotpCode(generateTotpSecret(), '000000');
    expect(result.valid).toBe(false);
  });
});

describe('recovery codes', () => {
  it('generates the configured number of transcribable codes', () => {
    const codes = generateRecoveryCodes();
    expect(codes).toHaveLength(RECOVERY_CODE_COUNT);
    for (const code of codes) {
      expect(code).toMatch(/^[A-Z2-9]{5}-[A-Z2-9]{5}$/);
    }
  });

  it('omits glyphs that are easy to misread', () => {
    const joined = generateRecoveryCodes(50).join('');
    for (const ambiguous of ['I', 'O', '0', '1']) {
      expect(joined).not.toContain(ambiguous);
    }
  });

  it('does not repeat within a batch', () => {
    const codes = generateRecoveryCodes(20);
    expect(new Set(codes).size).toBe(codes.length);
  });

  it('hashes case- and whitespace-insensitively', () => {
    const code = generateRecoveryCodes(1)[0] as string;
    expect(hashRecoveryCode(code.toLowerCase())).toBe(hashRecoveryCode(code));
    expect(hashRecoveryCode(`  ${code}  `)).toBe(hashRecoveryCode(code));
  });

  it('matches a stored digest and returns the digest that matched', () => {
    const codes = generateRecoveryCodes();
    const stored = codes.map(hashRecoveryCode);
    const target = codes[3] as string;

    expect(matchRecoveryCode(target, stored)).toBe(hashRecoveryCode(target));
  });

  it('returns null for a code that is not in the list', () => {
    const stored = generateRecoveryCodes().map(hashRecoveryCode);
    expect(matchRecoveryCode('AAAAA-BBBBB', stored)).toBeNull();
  });

  it('returns null against an empty list', () => {
    expect(matchRecoveryCode('AAAAA-BBBBB', [])).toBeNull();
  });
});
