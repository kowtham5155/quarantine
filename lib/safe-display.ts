/**
 * Rendering guards for package-derived strings (CLAUDE.md — treat every string
 * from a package as hostile input when rendering it).
 *
 * React escapes HTML for us. What it does not do is stop a package name that
 * contains bidirectional override characters from reordering the surrounding
 * UI, or a 40 KB "description" from destroying a table row. These helpers run
 * on anything that came out of a tarball or a registry response.
 */

/**
 * Bidi controls (Trojan Source, CVE-2021-42574), zero-width characters used for
 * homoglyph smuggling, and the soft hyphen / BOM pair that hides in plain text.
 */
const INVISIBLE_OR_BIDI =
  /[\u00AD\u061C\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;

/** C0/C1 control characters, except tab and newline which callers may want. */
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;

export const REPLACEMENT = '\uFFFD';

/** Remove bidi/zero-width characters that can reorder or hide adjacent text. */
export function stripBidiControls(value: string): string {
  return value.replace(INVISIBLE_OR_BIDI, '');
}

/** True when a string contains characters that could misrepresent it visually. */
export function containsDeceptiveCharacters(value: string): boolean {
  INVISIBLE_OR_BIDI.lastIndex = 0;
  return INVISIBLE_OR_BIDI.test(value);
}

export interface SafeTextOptions {
  /** Hard cap on rendered length. Longer input is truncated with an ellipsis. */
  maxLength?: number;
  /** Collapse runs of whitespace (including newlines) into single spaces. */
  collapseWhitespace?: boolean;
}

/**
 * Normalise an untrusted string for display: strip invisible and control
 * characters, optionally collapse whitespace, and bound the length.
 */
export function safeText(value: unknown, options: SafeTextOptions = {}): string {
  const { maxLength = 512, collapseWhitespace = true } = options;

  if (typeof value !== 'string') {
    return value === null || value === undefined ? '' : String(value);
  }

  let out = stripBidiControls(value).replace(CONTROL_CHARS, REPLACEMENT);
  if (collapseWhitespace) {
    out = out.replace(/\s+/g, ' ').trim();
  }
  if (out.length > maxLength) {
    out = `${out.slice(0, maxLength - 1)}…`;
  }
  return out;
}

/** Shorten a hex digest for display, keeping enough of it to be recognisable. */
export function shortHash(digest: string, length = 12): string {
  const cleaned = digest.replace(/[^a-fA-F0-9]/g, '');
  return cleaned.length <= length ? cleaned : cleaned.slice(0, length);
}
