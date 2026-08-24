/**
 * String distance and confusable normalisation for the typosquat family.
 *
 * Kept separate from the signal module so it can be tested exhaustively against
 * known typosquat pairs without constructing an AnalysisContext.
 */

/**
 * Damerau-Levenshtein distance with adjacent transposition.
 *
 * Plain Levenshtein counts a transposition (`recat` for `react`) as two edits,
 * which is wrong for this purpose: swapping two adjacent characters is the most
 * common typing error there is, and it is the single most common typosquat
 * technique. Counting it as one edit is the whole reason for using this variant.
 *
 * `limit` allows early exit: the caller only cares about distances at or below
 * TYPOSQUAT_MAX_DISTANCE, and abandoning a hopeless comparison early turns an
 * O(n·m) scan over a thousand candidates into something that finishes.
 */
export function damerauLevenshtein(a: string, b: string, limit = Infinity): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  // A length gap alone already exceeds the budget.
  if (Math.abs(a.length - b.length) > limit) return limit + 1;

  const rows = a.length + 1;
  const columns = b.length + 1;

  let previousPrevious = new Array<number>(columns).fill(0);
  let previous = new Array<number>(columns);
  let current = new Array<number>(columns);

  for (let column = 0; column < columns; column++) previous[column] = column;

  for (let row = 1; row < rows; row++) {
    current[0] = row;
    let rowMinimum = current[0] ?? row;

    for (let column = 1; column < columns; column++) {
      const cost = a[row - 1] === b[column - 1] ? 0 : 1;

      let value = Math.min(
        (current[column - 1] ?? Infinity) + 1, // insertion
        (previous[column] ?? Infinity) + 1, // deletion
        (previous[column - 1] ?? Infinity) + cost, // substitution
      );

      // Transposition of two adjacent characters.
      if (
        row > 1 &&
        column > 1 &&
        a[row - 1] === b[column - 2] &&
        a[row - 2] === b[column - 1]
      ) {
        value = Math.min(value, (previousPrevious[column - 2] ?? Infinity) + 1);
      }

      current[column] = value;
      if (value < rowMinimum) rowMinimum = value;
    }

    // Every remaining path is already over budget.
    if (rowMinimum > limit) return limit + 1;

    previousPrevious = previous;
    previous = current;
    current = new Array<number>(columns);
  }

  return previous[columns - 1] ?? 0;
}

// ---------------------------------------------------------------------------
// Homoglyphs and confusables
// ---------------------------------------------------------------------------

/**
 * Characters that render close enough to an ASCII character to fool a reader.
 *
 * Drawn from the Unicode confusables set, restricted to the substitutions that
 * are actually usable in a package name — npm normalises names to lowercase and
 * rejects most non-ASCII, but PyPI is more permissive, and a homoglyph in a
 * README install command works on either.
 */
const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  'а': 'a',
  'е': 'e',
  'о': 'o',
  'р': 'p',
  'с': 'c',
  'х': 'x',
  'у': 'y',
  'в': 'b',
  'м': 'm',
  'н': 'h',
  'і': 'i',
  'ј': 'j',
  'ѕ': 's',
  // Greek
  'α': 'a',
  'ο': 'o',
  'ρ': 'p',
  'ν': 'v',
  'ι': 'i',
  'κ': 'k',
  'υ': 'u',
  'χ': 'x',
  // Fullwidth
  'ａ': 'a',
  'ｅ': 'e',
  'ｏ': 'o',
  // Latin lookalikes and digits
  'ı': 'i',
  'ł': 'l',
  'ơ': 'o',
  'ɡ': 'g',
  '0': 'o',
  '1': 'l',
  '5': 's',
  '3': 'e',
};

/** True when the name contains a character that impersonates an ASCII one. */
export function hasConfusableCharacters(name: string): boolean {
  for (const character of name) {
    if (character.charCodeAt(0) > 127 && CONFUSABLES[character] !== undefined) return true;
  }
  return false;
}

/** Any non-ASCII character at all, which is unusual in a package name. */
export function hasNonAscii(name: string): boolean {
  return /[^\u0000-\u007F]/.test(name);
}

/** Map confusables to their ASCII lookalike, so squats collapse onto targets. */
export function foldConfusables(name: string): string {
  let out = '';
  for (const character of name) out += CONFUSABLES[character] ?? character;
  return out;
}

// ---------------------------------------------------------------------------
// Separator and scope normalisation
// ---------------------------------------------------------------------------

/**
 * Collapse separators so `foo-bar`, `foo_bar`, `foo.bar` and `foobar` compare
 * equal. This is Q-TYP-003's whole mechanism: the names are visually distinct
 * but semantically identical to a hurried reader.
 */
export function stripSeparators(name: string): string {
  return name.replace(/[-_.]/g, '');
}

/** Canonical form for equality: lowercase, confusables folded, separators gone. */
export function canonicalName(name: string): string {
  return stripSeparators(foldConfusables(name.toLowerCase()));
}

export interface ScopeParts {
  scope: string | null;
  name: string;
}

export function splitScope(fullName: string): ScopeParts {
  if (!fullName.startsWith('@')) return { scope: null, name: fullName };
  const slash = fullName.indexOf('/');
  if (slash < 0) return { scope: null, name: fullName };
  return { scope: fullName.slice(1, slash), name: fullName.slice(slash + 1) };
}

/**
 * Detect scope confusion: `@types/foo` impersonated as `types-foo`, `typesfoo`
 * or `@typesfoo/foo`.
 *
 * The attack relies on the scope being the security boundary — anyone can
 * publish `typesfoo`, nobody but the owner can publish inside `@types`.
 */
export function looksLikeScopeConfusion(
  candidate: string,
  target: string,
): { confused: true; technique: string } | null {
  const candidateParts = splitScope(candidate);
  const targetParts = splitScope(target);

  if (!targetParts.scope) return null;

  // The scope was flattened into the name: @types/node -> types-node, typesnode
  if (!candidateParts.scope) {
    const flattened = canonicalName(`${targetParts.scope}${targetParts.name}`);
    if (canonicalName(candidate) === flattened) {
      return { confused: true, technique: 'scope flattened into the name' };
    }
  }

  // A scope that impersonates the real one: @types-x/node, @typesx/node
  if (
    candidateParts.scope &&
    candidateParts.scope !== targetParts.scope &&
    canonicalName(candidateParts.name) === canonicalName(targetParts.name) &&
    damerauLevenshtein(canonicalName(candidateParts.scope), canonicalName(targetParts.scope), 3) <= 2
  ) {
    return { confused: true, technique: 'scope impersonated' };
  }

  return null;
}
