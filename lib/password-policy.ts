/**
 * Password policy constants.
 *
 * Kept in their own module because the registration and reset forms render them
 * in the browser, and `lib/password.ts` pulls in argon2 (a native addon) and the
 * full zxcvbn dictionary — neither of which belongs in a client bundle.
 */

export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_LENGTH = 256;
export const MIN_ZXCVBN_SCORE = 3;

/** Human labels for a zxcvbn 0–4 score. */
export const PASSWORD_SCORE_LABELS: Record<number, string> = {
  0: 'Too weak',
  1: 'Weak',
  2: 'Fair',
  3: 'Strong',
  4: 'Very strong',
};
