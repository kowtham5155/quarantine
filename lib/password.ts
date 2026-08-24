import { hash, verify } from '@node-rs/argon2';
import { MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, MIN_ZXCVBN_SCORE } from '@/lib/password-policy';
import { ZxcvbnFactory } from '@zxcvbn-ts/core';
import * as zxcvbnCommon from '@zxcvbn-ts/language-common';
import * as zxcvbnEn from '@zxcvbn-ts/language-en';

/**
 * Password hashing and strength policy.
 *
 * Argon2id at parameters that cost roughly 50ms on the deployment target —
 * enough to make offline cracking expensive without making a login feel slow.
 * Strength is measured with zxcvbn rather than a character-class rule, because
 * `Passw0rd!` satisfies every character-class rule ever written and is still
 * trivially guessable.
 */

export { MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH, MIN_ZXCVBN_SCORE } from '@/lib/password-policy';

const ARGON2_OPTIONS = {
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
} as const;

/**
 * zxcvbn-ts v4 is factory-based. Building the factory loads and ranks the whole
 * dictionary, so it is constructed once at module scope rather than per call.
 */
const zxcvbn = new ZxcvbnFactory({
  translations: zxcvbnEn.translations,
  graphs: zxcvbnCommon.adjacencyGraphs,
  dictionary: {
    ...zxcvbnCommon.dictionary,
    ...zxcvbnEn.dictionary,
  },
});

export function hashPassword(plaintext: string): Promise<string> {
  return hash(plaintext, ARGON2_OPTIONS);
}

/**
 * Verify a password against a stored hash. Never throws on a malformed hash —
 * a corrupt row must read as "wrong password", not as a 500 that tells an
 * attacker the account exists.
 */
export async function verifyPassword(digest: string, plaintext: string): Promise<boolean> {
  try {
    return await verify(digest, plaintext, ARGON2_OPTIONS);
  } catch {
    return false;
  }
}

export interface PasswordStrength {
  score: 0 | 1 | 2 | 3 | 4;
  acceptable: boolean;
  warning: string | null;
  suggestions: string[];
  /** Order-of-magnitude guesses needed, for the meter's tooltip. */
  guessesLog10: number;
}

/**
 * Score a password. `userInputs` should carry the email and name so zxcvbn can
 * penalise passwords derived from them.
 */
export async function scorePassword(
  plaintext: string,
  userInputs: string[] = [],
): Promise<PasswordStrength> {
  const result = await zxcvbn.checkAsync(plaintext, userInputs.filter(Boolean));
  const score = result.score as 0 | 1 | 2 | 3 | 4;

  return {
    score,
    acceptable: score >= MIN_ZXCVBN_SCORE && plaintext.length >= MIN_PASSWORD_LENGTH,
    warning: result.feedback.warning || null,
    suggestions: result.feedback.suggestions ?? [],
    guessesLog10: result.guessesLog10,
  };
}

export interface PasswordPolicyResult {
  ok: boolean;
  /** Human-readable reasons, safe to show on the form. */
  problems: string[];
  strength: PasswordStrength;
}

/** The full policy gate applied at registration and on every password change. */
export async function checkPasswordPolicy(
  plaintext: string,
  userInputs: string[] = [],
): Promise<PasswordPolicyResult> {
  const problems: string[] = [];

  if (plaintext.length < MIN_PASSWORD_LENGTH) {
    problems.push(`Use at least ${MIN_PASSWORD_LENGTH} characters.`);
  }
  if (plaintext.length > MAX_PASSWORD_LENGTH) {
    problems.push(`Use at most ${MAX_PASSWORD_LENGTH} characters.`);
  }

  const strength = await scorePassword(plaintext, userInputs);

  if (strength.score < MIN_ZXCVBN_SCORE) {
    problems.push(strength.warning ?? 'This password is too easy to guess.');
    for (const suggestion of strength.suggestions.slice(0, 2)) {
      problems.push(suggestion);
    }
  }

  return { ok: problems.length === 0, problems, strength };
}
