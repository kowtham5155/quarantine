import { afterEach, describe, expect, it } from 'vitest';

import { ENCODED_LITERAL_MIN_BYTES, ENTROPY_BITS_PER_CHAR } from '@/lib/engine/thresholds';
import {
  OBFUSCATION_RULES,
  analyseObfuscation,
  shannonEntropy,
} from '@/lib/engine/signals/obfuscation';

import { buildContext, cleanupFixtures, firedIds, signalFor } from './fixture';

/**
 * FAMILY 2 — obfuscation and evasion.
 *
 * SAFETY: every fixture below is a hand-written string. The module parses it
 * with @babel/parser and reads its bytes. Nothing is executed, required,
 * imported or evaluated — including the fixtures that contain the literal text
 * `eval(`, which is matched as source, never run.
 */

/**
 * Bidirectional and zero-width characters are written as `\uXXXX` escapes
 * throughout, never as literals: a literal one in this file would be invisible
 * in review, which is precisely the attack Q-OBF-005 exists to catch.
 */

afterEach(cleanupFixtures);

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Deterministic pseudo-random base64, so entropy assertions never flake. */
function pseudoBase64(length: number, seed = 1): string {
  let state = seed;
  let out = '';
  for (let index = 0; index < length; index++) {
    // Park–Miller: fixed sequence, no dependency on the platform's RNG.
    state = (state * 48271) % 2147483647;
    out += BASE64_ALPHABET[state % BASE64_ALPHABET.length];
  }
  return out;
}

const CLEAN_SOURCE = [
  "const path = require('path');",
  '',
  'function join(a, b) {',
  '  return path.join(a, b);',
  '}',
  '',
  'module.exports = { join };',
  '',
].join('\n');

describe('shannonEntropy', () => {
  it('is zero for a single repeated character', () => {
    expect(shannonEntropy('aaaaaaaa')).toBe(0);
  });

  it('is one bit for an even two-symbol alphabet', () => {
    expect(shannonEntropy('abababab')).toBeCloseTo(1, 10);
  });

  it('is zero for an empty string rather than NaN', () => {
    expect(shannonEntropy('')).toBe(0);
  });

  it('puts English prose below the encoded-data threshold', () => {
    const prose =
      'the quick brown fox jumps over the lazy dog and then goes back to sleep again';
    expect(shannonEntropy(prose)).toBeLessThan(ENTROPY_BITS_PER_CHAR);
  });

  it('puts random base64 above it', () => {
    expect(shannonEntropy(pseudoBase64(512))).toBeGreaterThan(ENTROPY_BITS_PER_CHAR);
  });
});

describe('analyseObfuscation', () => {
  it('evaluates every rule in the family', async () => {
    const context = await buildContext({ files: [{ path: 'index.js', content: CLEAN_SOURCE }] });
    const { signals } = await analyseObfuscation(context);

    expect(signals.map((signal) => signal.ruleId).sort()).toEqual([...OBFUSCATION_RULES].sort());
    expect(signals.every((signal) => signal.family === 'OBFUSCATION')).toBe(true);
  });

  it('fires nothing on ordinary readable source', async () => {
    const context = await buildContext({ files: [{ path: 'index.js', content: CLEAN_SOURCE }] });
    const { signals } = await analyseObfuscation(context);

    expect([...firedIds(signals)]).toEqual([]);
  });

  it('fires nothing on a package with no JavaScript at all', async () => {
    const context = await buildContext({
      files: [{ path: 'README.md', content: '# hello\n' }],
    });
    const { signals } = await analyseObfuscation(context);

    expect([...firedIds(signals)]).toEqual([]);
  });

  describe('Q-OBF-001 — high-entropy string literals', () => {
    it('fires on a long random-looking literal', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: `const k = "${pseudoBase64(200)}";\n` }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-001')).toBe(true);
      const detail = signalFor(signals, 'Q-OBF-001').evidence[0]?.detail;
      expect(Number(detail?.entropyBitsPerChar)).toBeGreaterThan(ENTROPY_BITS_PER_CHAR);
    });

    it('does not fire on a long literal of ordinary prose', async () => {
      const prose =
        'this is a perfectly ordinary sentence that happens to be quite long indeed, longer than the entropy floor';
      const context = await buildContext({
        files: [{ path: 'index.js', content: `const message = "${prose}";\n` }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-001')).toBe(false);
    });

    it('does not fire on a short literal, whose entropy is unstable', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: 'const k = "a1b2c3d4";\n' }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-001')).toBe(false);
    });

    it('raises confidence for entropy in the certainly-encoded range', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: `const k = "${pseudoBase64(4000)}";\n` }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(signalFor(signals, 'Q-OBF-001').confidence).toBeGreaterThan(0.8);
    });
  });

  describe('Q-OBF-002 — large encoded literals', () => {
    it('fires on a base64 blob above the size floor', async () => {
      const blob = pseudoBase64(ENCODED_LITERAL_MIN_BYTES + 200, 7);
      const context = await buildContext({
        files: [{ path: 'payload.js', content: `module.exports = "${blob}";\n` }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-002')).toBe(true);
      expect(signalFor(signals, 'Q-OBF-002').evidence[0]?.detail?.encoding).toBe('base64');
    });

    it('does not fire on a blob below the size floor', async () => {
      const blob = pseudoBase64(300, 11);
      const context = await buildContext({
        files: [{ path: 'payload.js', content: `module.exports = "${blob}";\n` }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-002')).toBe(false);
    });
  });

  describe('Q-OBF-003 — dynamic evaluation', () => {
    it('fires on a direct eval call', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: 'const run = (s) => eval(s);\nmodule.exports = run;\n' }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-003')).toBe(true);
      expect(signalFor(signals, 'Q-OBF-003').evidence[0]?.detail?.callee).toBe('eval');
    });

    it('fires on the Function constructor', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: 'module.exports = new Function("return 1");\n' }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-003')).toBe(true);
    });

    it('fires on a require with a computed specifier', async () => {
      const context = await buildContext({
        files: [
          {
            path: 'index.js',
            content: 'const name = process.env.M;\nmodule.exports = require(name);\n',
          },
        ],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-003')).toBe(true);
    });

    it('does not fire on a require with a plain string specifier', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: "module.exports = require('fs');\n" }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-003')).toBe(false);
    });

    it('fires on vm.runInNewContext', async () => {
      const context = await buildContext({
        files: [
          {
            path: 'index.js',
            content: "const vm = require('vm');\nvm.runInNewContext('1 + 1');\n",
          },
        ],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-003')).toBe(true);
    });
  });

  describe('Q-OBF-004 — obfuscator output', () => {
    it('fires on a large encoded string table', async () => {
      const members = Array.from({ length: 60 }, (_, index) =>
        `"${index.toString(16).padStart(2, '0').repeat(6)}"`,
      ).join(',');
      const context = await buildContext({
        files: [{ path: 'index.js', content: `const table = [${members}];\nmodule.exports = table;\n` }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-004')).toBe(true);
      expect(Number(signalFor(signals, 'Q-OBF-004').evidence[0]?.detail?.members)).toBe(60);
    });

    it('does not fire on a legitimate table of readable constants', async () => {
      const members = Array.from({ length: 60 }, (_, index) => `"unit-name-${index}"`).join(',');
      const context = await buildContext({
        files: [{ path: 'index.js', content: `const units = [${members}];\nmodule.exports = units;\n` }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-004')).toBe(false);
    });

    it('fires on hex-mangled identifiers', async () => {
      const body = Array.from({ length: 12 }, (_, index) => `var _0x${index}a4f2 = ${index};`).join(
        '\n',
      );
      const context = await buildContext({
        files: [{ path: 'index.js', content: `${body}\n` }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-004')).toBe(true);
      expect(Number(signalFor(signals, 'Q-OBF-004').evidence[0]?.detail?.mangledIdentifiers)).toBe(
        12,
      );
    });
  });

  describe('Q-OBF-005 — Trojan Source', () => {
    it('fires on a bidirectional override in source', async () => {
      const context = await buildContext({
        files: [
          {
            path: 'index.js',
            content: 'if (level === "user") {\n  // \u202E do not run \u202C\n}\n',
          },
        ],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-005')).toBe(true);
      expect(signalFor(signals, 'Q-OBF-005').evidence[0]?.detail?.codePoint).toBe('U+202E');
    });

    it('strips the control characters out of the excerpt it reports', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: 'const a = 1; // \u202E reversed\n' }],
      });
      const { signals } = await analyseObfuscation(context);

      const excerpt = signalFor(signals, 'Q-OBF-005').evidence[0]?.excerpt ?? '';
      expect(excerpt).not.toMatch(/[\u202A-\u202E\u2066-\u2069]/);
    });

    it('fires on a README, not just on source', async () => {
      const context = await buildContext({
        files: [
          { path: 'index.js', content: CLEAN_SOURCE },
          { path: 'README.md', content: '# safe\n\n\u202E look harmless \u202C\n' },
        ],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-005')).toBe(true);
      expect(signalFor(signals, 'Q-OBF-005').evidence[0]?.file).toBe('README.md');
    });

    it('fires on a run of zero-width characters', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: 'const a\u200B = 1;\nconst b\u200B = 2;\nconst c\u200B = 3;\n' }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-005')).toBe(true);
    });

    it('does not fire on a single zero-width character, which can be incidental', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: 'const a = "x\u200By";\n' }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-005')).toBe(false);
    });
  });

  describe('Q-OBF-006 — undeclared minification', () => {
    const longLine = Array.from({ length: 600 }, (_, index) => `var a${index}=${index};`).join('');

    it('fires on a large single-line bundle with no .min name and no source map', async () => {
      const context = await buildContext({
        files: [{ path: 'bundle.js', content: longLine }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-006')).toBe(true);
    });

    it('does not fire when the file declares itself minified', async () => {
      const context = await buildContext({
        files: [{ path: 'bundle.min.js', content: longLine }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-006')).toBe(false);
    });

    it('does not fire when a source map is referenced', async () => {
      const context = await buildContext({
        files: [{ path: 'bundle.js', content: `${longLine}\n//# sourceMappingURL=bundle.js.map` }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-006')).toBe(false);
    });

    it('does not fire when a sibling map file ships alongside', async () => {
      const context = await buildContext({
        files: [
          { path: 'bundle.js', content: longLine },
          { path: 'bundle.js.map', content: '{"version":3}' },
        ],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-006')).toBe(false);
    });
  });

  describe('Q-OBF-007 — constructed identifiers', () => {
    it('fires on deeply nested string concatenation', async () => {
      const chain = Array.from({ length: 12 }, (_, index) => `"p${index}"`).join(' + ');
      const context = await buildContext({
        files: [{ path: 'index.js', content: `const name = ${chain};\nmodule.exports = name;\n` }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-007')).toBe(true);
      expect(
        Number(signalFor(signals, 'Q-OBF-007').evidence[0]?.detail?.concatenationDepth),
      ).toBeGreaterThanOrEqual(8);
    });

    it('does not fire on ordinary two-part concatenation', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: 'const greeting = "hello " + name;\n' }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-007')).toBe(false);
    });

    it('fires on a long hex escape run', async () => {
      const escapes = '\\x41'.repeat(30);
      const context = await buildContext({
        files: [{ path: 'index.js', content: `const s = "${escapes}";\n` }],
      });
      const { signals } = await analyseObfuscation(context);

      expect(firedIds(signals).has('Q-OBF-007')).toBe(true);
    });
  });

  it('reports every fired signal against a real file path', async () => {
    const context = await buildContext({
      files: [{ path: 'lib/payload.js', content: `const k = "${pseudoBase64(300)}";\neval(k);\n` }],
    });
    const { signals } = await analyseObfuscation(context);

    for (const signal of signals.filter((candidate) => candidate.fired)) {
      for (const record of signal.evidence) {
        if (record.file !== undefined) expect(record.file).toBe('lib/payload.js');
      }
    }
  });
});
