import { afterEach, describe, expect, it } from 'vitest';

import { PROVENANCE_EXTRA_FILE_TOLERANCE } from '@/lib/engine/thresholds';
import {
  PROVENANCE_RULES,
  analyseProvenance,
  buildSnapshot,
  candidateTags,
  compareTrees,
  hashNormalised,
  isNormalisedAway,
} from '@/lib/engine/signals/provenance';

import { buildContext, cleanupFixtures, firedIds, signalFor, snapshotOf } from './fixture';

/**
 * FAMILY 6 — provenance.
 *
 * The event-stream question: does the published tarball match the source
 * anyone reviewed? These tests pin both halves of that — the divergence it must
 * catch, and the routine packaging differences it must not mistake for one.
 *
 * SAFETY: no repository is fetched. The snapshots are built in memory from
 * strings, and the tarball side is files written to a temp directory and read
 * as bytes.
 */

afterEach(cleanupFixtures);

const REPO_URL = 'https://github.com/acme/fixture';
const INDEX = "module.exports = () => 'ok';\n";
const README = '# fixture\n';

describe('analyseProvenance', () => {
  it('evaluates every rule in the family', async () => {
    const context = await buildContext({
      repositoryUrl: REPO_URL,
      files: [{ path: 'index.js', content: INDEX }],
      repository: snapshotOf({ 'index.js': INDEX }),
    });
    const { signals } = await analyseProvenance(context);

    expect(signals.map((signal) => signal.ruleId).sort()).toEqual([...PROVENANCE_RULES].sort());
    expect(signals.every((signal) => signal.family === 'PROVENANCE')).toBe(true);
  });

  describe('Q-PRV-001 — no declared source', () => {
    it('fires when the package declares no repository', async () => {
      const context = await buildContext({ repositoryUrl: null });
      const { signals } = await analyseProvenance(context);

      expect(firedIds(signals).has('Q-PRV-001')).toBe(true);
    });

    it('skips every comparison rule, because there is nothing to compare against', async () => {
      const context = await buildContext({ repositoryUrl: null });
      const { signals } = await analyseProvenance(context);

      for (const ruleId of ['Q-PRV-002', 'Q-PRV-003', 'Q-PRV-004'] as const) {
        expect(signalFor(signals, ruleId).skipped).toBe('NO_REPO');
        expect(signalFor(signals, ruleId).fired).toBe(false);
      }
    });

    it('does not fire when a repository is declared', async () => {
      const context = await buildContext({
        repositoryUrl: REPO_URL,
        repository: snapshotOf({ 'index.js': INDEX }),
        files: [{ path: 'index.js', content: INDEX }],
      });
      const { signals } = await analyseProvenance(context);

      expect(firedIds(signals).has('Q-PRV-001')).toBe(false);
    });
  });

  describe('Q-PRV-002 — the source could not be read', () => {
    it('fires when the declared repository could not be fetched', async () => {
      const context = await buildContext({ repositoryUrl: REPO_URL });
      const { signals } = await analyseProvenance(context);

      expect(firedIds(signals).has('Q-PRV-002')).toBe(true);
    });

    it('marks the comparison unreachable rather than passed', async () => {
      const context = await buildContext({ repositoryUrl: REPO_URL });
      const { signals } = await analyseProvenance(context);

      for (const ruleId of ['Q-PRV-003', 'Q-PRV-004'] as const) {
        expect(signalFor(signals, ruleId).skipped).toBe('REPO_UNREACHABLE');
      }
    });

    it('fires on an archived repository that is still publishing releases', async () => {
      const context = await buildContext({
        repositoryUrl: REPO_URL,
        files: [{ path: 'index.js', content: INDEX }],
        repository: snapshotOf({ 'index.js': INDEX }, { archived: true }),
      });
      const { signals } = await analyseProvenance(context);

      expect(firedIds(signals).has('Q-PRV-002')).toBe(true);
      // Archived is not unreachable: the comparison still happened.
      expect(signalFor(signals, 'Q-PRV-003').skipped).toBeUndefined();
    });
  });

  describe('Q-PRV-003 — code in the tarball that is not in the source', () => {
    it('fires at high confidence on an executable file that exists only in the tarball', async () => {
      const context = await buildContext({
        repositoryUrl: REPO_URL,
        files: [
          { path: 'index.js', content: INDEX },
          { path: 'payload.js', content: "require('child_process').exec('id');\n" },
        ],
        repository: snapshotOf({ 'index.js': INDEX }),
      });
      const { signals } = await analyseProvenance(context);

      const signal = signalFor(signals, 'Q-PRV-003');
      expect(signal.fired).toBe(true);
      expect(signal.confidence).toBeGreaterThan(0.9);
      expect(signal.evidence.map((record) => record.file)).toContain('payload.js');
    });

    it('does not fire on build output, which is expected to differ', async () => {
      const context = await buildContext({
        repositoryUrl: REPO_URL,
        files: [
          { path: 'index.js', content: INDEX },
          { path: 'dist/index.js', content: 'module.exports=1' },
          { path: 'dist/index.d.ts', content: 'export {}' },
          { path: 'index.js.map', content: '{}' },
        ],
        repository: snapshotOf({ 'index.js': INDEX }),
      });
      const { signals } = await analyseProvenance(context);

      expect(firedIds(signals).has('Q-PRV-003')).toBe(false);
    });

    it('tolerates a couple of extra non-executable files', async () => {
      const context = await buildContext({
        repositoryUrl: REPO_URL,
        files: [
          { path: 'index.js', content: INDEX },
          { path: 'data/a.txt', content: 'a' },
          { path: 'data/b.txt', content: 'b' },
        ],
        repository: snapshotOf({ 'index.js': INDEX }),
      });
      const { signals } = await analyseProvenance(context);

      expect(firedIds(signals).has('Q-PRV-003')).toBe(false);
    });

    it('fires at lower confidence once the extras exceed the tolerance', async () => {
      const extras = Array.from({ length: PROVENANCE_EXTRA_FILE_TOLERANCE + 2 }, (_, index) => ({
        path: `data/extra-${index}.txt`,
        content: `${index}`,
      }));
      const context = await buildContext({
        repositoryUrl: REPO_URL,
        files: [{ path: 'index.js', content: INDEX }, ...extras],
        repository: snapshotOf({ 'index.js': INDEX }),
      });
      const { signals } = await analyseProvenance(context);

      const signal = signalFor(signals, 'Q-PRV-003');
      expect(signal.fired).toBe(true);
      expect(signal.confidence).toBeLessThan(0.9);
    });

    it('passes when the tarball matches the source tree', async () => {
      const context = await buildContext({
        repositoryUrl: REPO_URL,
        files: [
          { path: 'index.js', content: INDEX },
          { path: 'README.md', content: README },
        ],
        repository: snapshotOf({ 'index.js': INDEX, 'README.md': README }),
      });
      const { signals } = await analyseProvenance(context);

      expect(firedIds(signals).has('Q-PRV-003')).toBe(false);
      expect(signalFor(signals, 'Q-PRV-003').skipped).toBeUndefined();
    });
  });

  describe('Q-PRV-004 — files that exist in both and differ', () => {
    it('fires when a shipped file does not match its reviewed source', async () => {
      const context = await buildContext({
        repositoryUrl: REPO_URL,
        files: [{ path: 'index.js', content: "module.exports = () => 'tampered';\n" }],
        repository: snapshotOf({ 'index.js': INDEX }),
      });
      const { signals } = await analyseProvenance(context);

      expect(firedIds(signals).has('Q-PRV-004')).toBe(true);
      expect(signalFor(signals, 'Q-PRV-004').evidence[0]?.file).toBe('index.js');
    });

    it('does not fire when the content is identical', async () => {
      const context = await buildContext({
        repositoryUrl: REPO_URL,
        files: [{ path: 'index.js', content: INDEX }],
        repository: snapshotOf({ 'index.js': INDEX }),
      });
      const { signals } = await analyseProvenance(context);

      expect(firedIds(signals).has('Q-PRV-004')).toBe(false);
    });

    it('reports no tag match rather than divergence when nothing overlapped', async () => {
      const context = await buildContext({
        repositoryUrl: REPO_URL,
        files: [{ path: 'src/index.js', content: INDEX }],
        repository: snapshotOf({ 'packages/core/index.js': INDEX }),
      });
      const { signals } = await analyseProvenance(context);

      expect(signalFor(signals, 'Q-PRV-004').skipped).toBe('NO_TAG_MATCH');
    });
  });

  describe('Q-PRV-005 — binary blobs in a package that claims to be source', () => {
    const blob = Buffer.alloc(20_000);

    it('fires on an undeclared binary above the size floor', async () => {
      const context = await buildContext({
        repositoryUrl: null,
        files: [{ path: 'vendor/blob.bin', content: blob }],
      });
      const { signals } = await analyseProvenance(context);

      expect(firedIds(signals).has('Q-PRV-005')).toBe(true);
      expect(Number(signalFor(signals, 'Q-PRV-005').evidence[0]?.detail?.bytes)).toBe(20_000);
    });

    it('does not fire when the package declares a native build', async () => {
      const context = await buildContext({
        repositoryUrl: null,
        files: [
          { path: 'binding.gyp', content: '{ "targets": [] }' },
          { path: 'build/addon.node', content: blob },
        ],
      });
      const { signals } = await analyseProvenance(context);

      expect(firedIds(signals).has('Q-PRV-005')).toBe(false);
    });

    it('does not fire on ordinary media, which is not a payload', async () => {
      const context = await buildContext({
        repositoryUrl: null,
        files: [{ path: 'assets/logo.png', content: blob }],
      });
      const { signals } = await analyseProvenance(context);

      expect(firedIds(signals).has('Q-PRV-005')).toBe(false);
    });

    it('does not fire on a small binary, which is usually a test fixture', async () => {
      const context = await buildContext({
        repositoryUrl: null,
        files: [{ path: 'vendor/small.bin', content: Buffer.alloc(64) }],
      });
      const { signals } = await analyseProvenance(context);

      expect(firedIds(signals).has('Q-PRV-005')).toBe(false);
    });
  });

  describe('Q-PRV-006 — provenance attestation', () => {
    it('fires when no attestation was published', async () => {
      const context = await buildContext({ repositoryUrl: null });
      const { signals } = await analyseProvenance(context);

      expect(firedIds(signals).has('Q-PRV-006')).toBe(true);
    });
  });

  it('reproduces the event-stream shape end to end', async () => {
    const context = await buildContext({
      name: 'event-stream',
      version: '3.3.6',
      repositoryUrl: 'https://github.com/dominictarr/event-stream',
      files: [
        { path: 'index.js', content: INDEX },
        { path: 'test/simple.js', content: 'require("../index.js");\n' },
        // The file reviewers never saw.
        { path: 'flatmap-stream.js', content: 'var e = "payload";\n' },
      ],
      repository: snapshotOf({ 'index.js': INDEX }),
    });
    const { signals } = await analyseProvenance(context);
    const signal = signalFor(signals, 'Q-PRV-003');

    expect(signal.fired).toBe(true);
    expect(signal.evidence.map((record) => record.file)).toEqual(['flatmap-stream.js']);
    // The test directory is normalised away, so it is not counted as divergence.
    expect(signal.evidence).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

describe('isNormalisedAway', () => {
  it.each([
    'node_modules/x/index.js',
    'dist/index.js',
    'lib/index.js',
    'types/index.d.ts',
    'bundle.min.js',
    'index.js.map',
    'package-lock.json',
    '.github/workflows/ci.yml',
    'test/unit.js',
    'index.test.js',
    'CHANGELOG.md',
    'tsconfig.json',
    'coverage/lcov.info',
  ])('normalises away %s', (path) => {
    expect(isNormalisedAway(path)).toBe(true);
  });

  it.each(['index.js', 'src/main.js', 'README.md', 'bin/cli.js', 'postinstall.js'])(
    'keeps %s, which a reviewer would expect to see',
    (path) => {
      expect(isNormalisedAway(path)).toBe(false);
    },
  );
});

describe('compareTrees', () => {
  const source = new Map([
    ['index.js', 'hash-a'],
    ['README.md', 'hash-b'],
  ]);

  it('splits the tarball into identical, modified and extra', () => {
    const comparison = compareTrees(
      [
        { path: 'index.js', sha256: 'hash-a' },
        { path: 'README.md', sha256: 'changed' },
        { path: 'extra.js', sha256: 'hash-c' },
      ],
      source,
    );

    expect(comparison.identical).toEqual(['index.js']);
    expect(comparison.modified).toEqual(['README.md']);
    expect(comparison.onlyInTarball).toEqual(['extra.js']);
    expect(comparison.executableOnlyInTarball).toEqual(['extra.js']);
  });

  it('separates extras that can run from extras that cannot', () => {
    const comparison = compareTrees(
      [
        { path: 'notes.txt', sha256: 'x' },
        { path: 'run.sh', sha256: 'y' },
      ],
      new Map(),
    );

    expect(comparison.onlyInTarball.sort()).toEqual(['notes.txt', 'run.sh']);
    expect(comparison.executableOnlyInTarball).toEqual(['run.sh']);
  });

  it('reports files present only in source, without treating them as a signal', () => {
    const comparison = compareTrees([{ path: 'index.js', sha256: 'hash-a' }], source);
    expect(comparison.onlyInSource).toEqual(['README.md']);
  });

  it('ignores normalised paths on both sides', () => {
    const comparison = compareTrees(
      [{ path: 'dist/index.js', sha256: 'x' }],
      new Map([['test/a.js', 'y']]),
    );

    expect(comparison.onlyInTarball).toEqual([]);
    expect(comparison.onlyInSource).toEqual([]);
  });
});

describe('candidateTags', () => {
  it('tries the conventions a project might use, v-prefixed first', () => {
    expect(candidateTags('1.2.3')).toEqual([
      'v1.2.3',
      '1.2.3',
      'release-1.2.3',
      'releases/1.2.3',
      '1.2.3-release',
    ]);
  });

  it('does not double the v when the version already has one', () => {
    expect(candidateTags('v1.2.3')[0]).toBe('v1.2.3');
  });
});

describe('hashNormalised', () => {
  it('ignores the line endings a Windows checkout introduces', () => {
    expect(hashNormalised(Buffer.from('a\r\nb\r\n'))).toBe(hashNormalised(Buffer.from('a\nb\n')));
  });

  it('still distinguishes different content', () => {
    expect(hashNormalised(Buffer.from('a\n'))).not.toBe(hashNormalised(Buffer.from('b\n')));
  });
});

describe('buildSnapshot', () => {
  it('hashes every file through the normaliser', () => {
    const snapshot = buildSnapshot(
      'github.com',
      'acme',
      'fixture',
      'v1.0.0',
      [{ path: 'index.js', content: Buffer.from(INDEX) }],
      false,
    );

    expect(snapshot.files.get('index.js')).toBe(hashNormalised(Buffer.from(INDEX)));
    expect(snapshot).toMatchObject({ host: 'github.com', owner: 'acme', tag: 'v1.0.0' });
  });
});
