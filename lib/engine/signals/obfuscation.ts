import { collectCalls, collectStringArrays, collectStrings, concatenationDepth, walk } from '@/lib/engine/ast';
import {
  CONCAT_DEPTH,
  ENCODED_LITERAL_HIGH_CONFIDENCE_BYTES,
  ENCODED_LITERAL_MIN_BYTES,
  ENTROPY_BITS_PER_CHAR,
  ENTROPY_HIGH_CONFIDENCE,
  ENTROPY_MIN_LENGTH,
  MINIFIED_AVG_LINE_LENGTH,
  MINIFIED_MIN_FILE_BYTES,
  STRING_ARRAY_ENCODED_RATIO,
  STRING_ARRAY_MIN_MEMBERS,
} from '@/lib/engine/thresholds';
import type { AnalysisContext, FamilyResult } from '@/lib/engine/types';
import {
  confidenceForSource,
  evidence,
  excerptAround,
  lineOf,
  loadSources,
  readText,
  runFamily,
} from '@/lib/engine/signals/helpers';

/**
 * FAMILY 2 — obfuscation and evasion.
 *
 * Obfuscation is not itself malicious: plenty of legitimate packages ship
 * minified bundles. What makes it matter is that it is a prerequisite for
 * hiding a payload, so these rules carry modest weight on their own and become
 * significant when they corroborate a capability or install signal.
 *
 * The exception is Q-OBF-005 (bidirectional control characters), which has no
 * benign explanation in package source and is weighted accordingly.
 */

export const OBFUSCATION_RULES = [
  'Q-OBF-001',
  'Q-OBF-002',
  'Q-OBF-003',
  'Q-OBF-004',
  'Q-OBF-005',
  'Q-OBF-006',
  'Q-OBF-007',
] as const;

/**
 * Shannon entropy in bits per character.
 *
 * Measured over the string's own alphabet, which is what makes it comparable
 * across encodings: base64 uses 64 symbols fairly evenly and lands near 6.0,
 * English prose reuses a few symbols heavily and lands near 4.2.
 */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;

  const counts = new Map<string, number>();
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

const BASE64_RUN = /[A-Za-z0-9+/=]{256,}/g;
const HEX_RUN = /(?:0x)?[0-9a-fA-F]{256,}/g;
const HEX_ESCAPE_RUN = /(?:\\x[0-9a-fA-F]{2}){20,}/g;

/**
 * Bidirectional and invisible control characters — Trojan Source, CVE-2021-42574.
 *
 * These reorder how source is *displayed* without changing how it *executes*,
 * so a reviewer reading the diff sees something different from what runs. There
 * is no legitimate reason for them to appear in package source.
 *
 * Written with explicit escapes so the file itself cannot be a Trojan Source
 * carrier — a literal bidi character here would be invisible in review.
 */
const BIDI_CONTROLS =
  /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g;

const ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF\u00AD]/g;

const EVAL_CALLEES = new Set([
  'eval',
  'Function',
  'globalThis.eval',
  'window.eval',
  'global.eval',
  'vm.runInThisContext',
  'vm.runInNewContext',
  'vm.compileFunction',
  'process.binding',
]);

export async function analyseObfuscation(context: AnalysisContext): Promise<FamilyResult> {
  return runFamily('OBFUSCATION', context, OBFUSCATION_RULES, async (builder) => {
    const { files } = context.artifact;
    const { sources } = await loadSources(files);

    const fired = new Set<string>();
    const mark = (ruleId: string): void => void fired.add(ruleId);

    for (const source of sources) {
      const { file, text, parsed } = source;

      // ---------------------------------------------------------------------
      // Q-OBF-001 — high-entropy string literals
      // ---------------------------------------------------------------------
      const literals = parsed.parsed
        ? collectStrings(parsed).map((record) => ({ value: record.value, line: record.line }))
        : extractLiteralsByRegex(text);

      for (const literal of literals) {
        if (literal.value.length < ENTROPY_MIN_LENGTH) continue;

        const entropy = shannonEntropy(literal.value);
        if (entropy < ENTROPY_BITS_PER_CHAR) continue;

        mark('Q-OBF-001');
        builder.fire(
          'Q-OBF-001',
          entropy >= ENTROPY_HIGH_CONFIDENCE
            ? confidenceForSource(source, 0.85)
            : confidenceForSource(source, 0.6),
          [
            evidence(file.path, literal.line, literal.value.slice(0, 120), {
              entropyBitsPerChar: Number(entropy.toFixed(2)),
              length: literal.value.length,
            }),
          ],
        );
        break; // one hit per file is enough to make the point
      }

      // ---------------------------------------------------------------------
      // Q-OBF-002 — large encoded literals
      // ---------------------------------------------------------------------
      for (const { pattern, encoding } of [
        { pattern: BASE64_RUN, encoding: 'base64' },
        { pattern: HEX_RUN, encoding: 'hex' },
      ]) {
        pattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(text)) !== null) {
          if (match[0].length < ENCODED_LITERAL_MIN_BYTES) continue;

          mark('Q-OBF-002');
          builder.fire(
            'Q-OBF-002',
            match[0].length >= ENCODED_LITERAL_HIGH_CONFIDENCE_BYTES ? 0.85 : 0.65,
            [
              evidence(file.path, lineOf(text, match.index), `${match[0].slice(0, 100)}…`, {
                encoding,
                bytes: match[0].length,
              }),
            ],
          );
          break;
        }
      }

      // ---------------------------------------------------------------------
      // Q-OBF-003 — dynamic evaluation
      // ---------------------------------------------------------------------
      if (parsed.parsed) {
        for (const call of collectCalls(parsed)) {
          if (!EVAL_CALLEES.has(call.callee)) continue;

          mark('Q-OBF-003');
          builder.fire('Q-OBF-003', confidenceForSource(source, 0.9), [
            evidence(file.path, call.line, excerptAround(text, indexOfLine(text, call.line)), {
              callee: call.callee,
            }),
          ]);
        }

        // `require(atob(...))` and friends: a require whose argument is a call
        // rather than a literal is resolving its target at runtime.
        walk(parsed.ast!, (node) => {
          if (node.type !== 'CallExpression') return;
          if (node.callee.type !== 'Identifier' || node.callee.name !== 'require') return;

          const argument = node.arguments[0];
          if (!argument || argument.type === 'StringLiteral') return;

          mark('Q-OBF-003');
          builder.fire('Q-OBF-003', confidenceForSource(source, 0.8), [
            evidence(file.path, undefined, 'require() with a computed specifier', {
              argumentType: argument.type,
            }),
          ]);
        });
      } else if (/\beval\s*\(|new\s+Function\s*\(/.test(text)) {
        // Byte-level fallback for a file the parser could not handle.
        const index = text.search(/\beval\s*\(|new\s+Function\s*\(/);
        mark('Q-OBF-003');
        builder.fire('Q-OBF-003', confidenceForSource(source, 0.9), [
          evidence(file.path, lineOf(text, index), excerptAround(text, index), {
            viaByteScan: true,
          }),
        ]);
      }

      // ---------------------------------------------------------------------
      // Q-OBF-004 — string-array + decoder, the JS-obfuscator signature
      // ---------------------------------------------------------------------
      if (parsed.parsed) {
        for (const array of collectStringArrays(parsed)) {
          if (array.members.length < STRING_ARRAY_MIN_MEMBERS) continue;

          const encodedMembers = array.members.filter(looksEncoded).length;
          if (encodedMembers / array.members.length < STRING_ARRAY_ENCODED_RATIO) continue;

          mark('Q-OBF-004');
          builder.fire('Q-OBF-004', 0.85, [
            evidence(file.path, array.line, array.members.slice(0, 4).join(', '), {
              members: array.members.length,
              encodedRatio: Number((encodedMembers / array.members.length).toFixed(2)),
            }),
          ]);
          break;
        }
      }

      // The `_0x1234` naming that obfuscators emit is a strong tell on its own.
      const mangled = /_0x[0-9a-f]{4,}/g;
      const mangledCount = (text.match(mangled) ?? []).length;
      if (mangledCount >= 10) {
        mark('Q-OBF-004');
        builder.fire('Q-OBF-004', 0.9, [
          evidence(file.path, undefined, undefined, { mangledIdentifiers: mangledCount }),
        ]);
      }

      // ---------------------------------------------------------------------
      // Q-OBF-005 — Trojan Source
      // ---------------------------------------------------------------------
      BIDI_CONTROLS.lastIndex = 0;
      const bidiMatch = BIDI_CONTROLS.exec(text);
      if (bidiMatch) {
        mark('Q-OBF-005');
        builder.fire('Q-OBF-005', 0.95, [
          evidence(
            file.path,
            lineOf(text, bidiMatch.index),
            // The excerpt has the control characters stripped, so pasting it
            // into a terminal or a report cannot reproduce the reordering.
            excerptAround(text, bidiMatch.index).replace(BIDI_CONTROLS, '�'),
            { codePoint: `U+${(bidiMatch[0].codePointAt(0) ?? 0).toString(16).toUpperCase()}` },
          ),
        ]);
      }

      ZERO_WIDTH.lastIndex = 0;
      const zeroWidth = text.match(ZERO_WIDTH);
      if (zeroWidth && zeroWidth.length >= 3) {
        mark('Q-OBF-005');
        builder.fire('Q-OBF-005', 0.7, [
          evidence(file.path, undefined, undefined, { zeroWidthCharacters: zeroWidth.length }),
        ]);
      }

      // ---------------------------------------------------------------------
      // Q-OBF-006 — minified without a `.min` name and without a source map
      // ---------------------------------------------------------------------
      if (file.size >= MINIFIED_MIN_FILE_BYTES) {
        const lines = text.split('\n');
        const average = text.length / Math.max(1, lines.length);
        const declaresMin = /\.min\.[cm]?jsx?$/i.test(file.path);
        const hasSourceMap = /\/\/[#@]\s*sourceMappingURL=/.test(text);
        const hasSibling = files.some((candidate) => candidate.path === `${file.path}.map`);

        if (average > MINIFIED_AVG_LINE_LENGTH && !declaresMin && !hasSourceMap && !hasSibling) {
          mark('Q-OBF-006');
          builder.fire('Q-OBF-006', 0.6, [
            evidence(file.path, undefined, undefined, {
              averageLineLength: Math.round(average),
              bytes: file.size,
            }),
          ]);
        }
      }

      // ---------------------------------------------------------------------
      // Q-OBF-007 — deep concatenation building identifiers
      // ---------------------------------------------------------------------
      if (parsed.parsed && parsed.ast) {
        let deepest = 0;
        let deepestLine = 1;

        walk(parsed.ast, (node) => {
          if (node.type !== 'BinaryExpression' || node.operator !== '+') return;
          const depth = concatenationDepth(node);
          if (depth > deepest) {
            deepest = depth;
            deepestLine = lineOf(text, node.start ?? 0);
          }
        });

        if (deepest >= CONCAT_DEPTH) {
          mark('Q-OBF-007');
          builder.fire('Q-OBF-007', 0.7, [
            evidence(file.path, deepestLine, undefined, { concatenationDepth: deepest }),
          ]);
        }
      }

      // Hex escape runs are the non-AST form of the same idea.
      HEX_ESCAPE_RUN.lastIndex = 0;
      const escapeRun = HEX_ESCAPE_RUN.exec(text);
      if (escapeRun) {
        mark('Q-OBF-007');
        builder.fire('Q-OBF-007', 0.75, [
          evidence(file.path, lineOf(text, escapeRun.index), `${escapeRun[0].slice(0, 80)}…`, {
            escapeRunLength: escapeRun[0].length,
          }),
        ]);
      }
    }

    // Non-source files can still carry Trojan Source — a README that renders in
    // a package listing, or a .md changelog quoting "safe" code.
    for (const file of files) {
      if (file.isBinary) continue;
      if (!/\.(md|txt|json|ya?ml)$/i.test(file.path)) continue;

      const text = await readText(file);
      if (text === null) continue;

      BIDI_CONTROLS.lastIndex = 0;
      const match = BIDI_CONTROLS.exec(text);
      if (!match) continue;

      mark('Q-OBF-005');
      builder.fire('Q-OBF-005', 0.8, [
        evidence(
          file.path,
          lineOf(text, match.index),
          excerptAround(text, match.index).replace(BIDI_CONTROLS, '�'),
          { codePoint: `U+${(match[0].codePointAt(0) ?? 0).toString(16).toUpperCase()}` },
        ),
      ]);
    }

    for (const ruleId of OBFUSCATION_RULES) {
      if (!fired.has(ruleId)) builder.pass(ruleId);
    }
  });
}

/** A member of an obfuscator string table: encoded, escaped, or non-word. */
function looksEncoded(value: string): boolean {
  if (value.length === 0) return true;
  if (/^[A-Za-z0-9+/=]{16,}$/.test(value)) return true;
  if (/^[0-9a-fA-F]{8,}$/.test(value)) return true;
  // Anything outside Basic Latin in an obfuscator table is encoded payload.
  if (/[\u0080-\uFFFF]/.test(value)) return true;
  if (!/^[\u0020-\u007e]*$/.test(value)) return true;
  return /^[^a-zA-Z]*$/.test(value);
}

/** Crude literal extraction for files the parser could not handle. */
function extractLiteralsByRegex(text: string): Array<{ value: string; line: number }> {
  const out: Array<{ value: string; line: number }> = [];
  const pattern = /(['"`])((?:\\.|(?!\1)[^\\]){32,})\1/g;

  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    const value = match[2];
    if (value) out.push({ value, line: lineOf(text, match.index) });
    if (out.length >= 500) break;
  }

  return out;
}

/** Character offset of the start of a 1-indexed line. */
function indexOfLine(text: string, line: number): number {
  if (line <= 1) return 0;
  let seen = 1;
  for (let index = 0; index < text.length; index++) {
    if (text[index] === '\n') {
      seen++;
      if (seen === line) return index + 1;
    }
  }
  return 0;
}
