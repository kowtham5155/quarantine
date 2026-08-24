import { gzipSync } from 'node:zlib';
import { existsSync } from 'node:fs';
import { readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { Pack } from 'tar';
import { afterEach, describe, expect, it } from 'vitest';

import {
  MAX_DEPTH,
  MAX_ENTRIES,
  MAX_FILE_BYTES,
  checkEntryPath,
  createScanDirectory,
  destroyScanDirectory,
  extractTarball,
  looksBinary,
  stripArchivePrefix,
  withScanDirectory,
} from '@/lib/engine/extract';

/**
 * Every archive here is built in memory. Nothing is downloaded, and nothing
 * extracted is ever executed — the tests assert on paths, sizes and hashes.
 */

// ---------------------------------------------------------------------------
// Archive construction helpers
// ---------------------------------------------------------------------------

interface FakeEntry {
  path: string;
  content: Buffer | string;
  /** Overrides the size written into the tar header, to fake a lying header. */
  declaredSize?: number;
}

/** Build a raw (ungzipped) tar from entries, writing headers by hand. */
function buildTar(entries: FakeEntry[]): Buffer {
  const blocks: Buffer[] = [];

  for (const entry of entries) {
    const content = Buffer.isBuffer(entry.content) ? entry.content : Buffer.from(entry.content);
    const header = Buffer.alloc(512);

    // POSIX ustar header. Only the fields the parser needs are populated.
    header.write(entry.path.slice(0, 100), 0, 100, 'utf8');
    header.write('0000644\0', 100, 8, 'utf8'); // mode
    header.write('0000000\0', 108, 8, 'utf8'); // uid
    header.write('0000000\0', 116, 8, 'utf8'); // gid
    const size = entry.declaredSize ?? content.length;
    header.write(size.toString(8).padStart(11, '0') + '\0', 124, 12, 'utf8');
    header.write('00000000000\0', 136, 12, 'utf8'); // mtime
    header.write('        ', 148, 8, 'utf8'); // checksum placeholder
    header.write('0', 156, 1, 'utf8'); // typeflag: regular file
    header.write('ustar\0', 257, 6, 'utf8');
    header.write('00', 263, 2, 'utf8');

    let checksum = 0;
    for (const byte of header) checksum += byte;
    header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'utf8');

    blocks.push(header);
    blocks.push(content);
    const padding = (512 - (content.length % 512)) % 512;
    if (padding > 0) blocks.push(Buffer.alloc(padding));
  }

  blocks.push(Buffer.alloc(1024)); // two zero blocks terminate the archive
  return Buffer.concat(blocks);
}

function buildTarGz(entries: FakeEntry[]): Buffer {
  return gzipSync(buildTar(entries));
}

/**
 * Pseudo-random bytes that gzip cannot meaningfully shrink, so a size-bomb
 * fixture exercises our own byte counters rather than node-tar's ratio guard.
 * Deterministic, so a failure is reproducible.
 */
function incompressible(size: number, seed: number): Buffer {
  const out = Buffer.alloc(size);
  let state = (seed + 1) * 0x9e3779b1;
  for (let index = 0; index < size; index++) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    out[index] = state & 0xff;
  }
  return out;
}

/** Build a tarball through node-tar itself, for the well-formed cases. */
async function buildRealTarGz(files: Record<string, string>): Promise<Buffer> {
  const pack = new Pack({ gzip: true, portable: true, noDirRecurse: true });
  const chunks: Buffer[] = [];
  pack.on('data', (chunk: Buffer) => chunks.push(chunk));

  const done = new Promise<void>((resolve, reject) => {
    pack.on('end', () => resolve());
    pack.on('error', reject);
  });

  // Pack reads from disk, so stage the files in a scratch dir first.
  const staging = await createScanDirectory();
  try {
    const { mkdir, writeFile } = await import('node:fs/promises');
    for (const [relative, content] of Object.entries(files)) {
      const absolute = path.join(staging, relative);
      await mkdir(path.dirname(absolute), { recursive: true });
      await writeFile(absolute, content);
    }
    pack.cwd = staging;
    for (const relative of Object.keys(files)) pack.add(relative);
    pack.end();
    await done;
    return Buffer.concat(chunks);
  } finally {
    await destroyScanDirectory(staging);
  }
}

const scanDirs: string[] = [];
async function scratch(): Promise<string> {
  const root = await createScanDirectory();
  scanDirs.push(root);
  return root;
}

afterEach(async () => {
  while (scanDirs.length > 0) {
    const root = scanDirs.pop();
    if (root) await destroyScanDirectory(root);
  }
});

async function walk(root: string): Promise<string[]> {
  const out: string[] = [];
  async function recurse(dir: string): Promise<void> {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const absolute = path.join(dir, entry.name);
      if (entry.isDirectory()) await recurse(absolute);
      else out.push(path.relative(root, absolute).split(path.sep).join('/'));
    }
  }
  await recurse(root);
  return out;
}

// ---------------------------------------------------------------------------
// Zip-slip
// ---------------------------------------------------------------------------

describe('checkEntryPath — zip-slip guard', () => {
  const root = '/tmp/quarantine-scan-abc';

  const escapes = [
    '../evil.js',
    '../../evil.js',
    '../../../../../../../../etc/passwd',
    'package/../../evil.js',
    'package/nested/../../../evil.js',
    './../evil.js',
    'a/b/c/../../../../evil.js',
  ];

  for (const entryPath of escapes) {
    it(`rejects ${entryPath}`, () => {
      const result = checkEntryPath(root, entryPath);
      expect(result.ok).toBe(false);
      expect(result.reason).toBe('PATH_ESCAPE');
    });
  }

  it('rejects absolute paths', () => {
    expect(checkEntryPath(root, '/etc/passwd')).toMatchObject({
      ok: false,
      reason: 'ABSOLUTE_PATH',
    });
    expect(checkEntryPath(root, '/tmp/quarantine-scan-abc/inside.js')).toMatchObject({
      ok: false,
      reason: 'ABSOLUTE_PATH',
    });
  });

  it('rejects a Windows drive letter', () => {
    expect(checkEntryPath(root, 'C:/windows/system32/evil.dll')).toMatchObject({
      ok: false,
      reason: 'ABSOLUTE_PATH',
    });
  });

  it('rejects backslash separators that would escape', () => {
    expect(checkEntryPath(root, '..\\..\\evil.js')).toMatchObject({
      ok: false,
      reason: 'PATH_ESCAPE',
    });
  });

  it('does not accept a sibling directory sharing the root prefix', () => {
    // /tmp/quarantine-scan-abc-evil starts with the root string but is not
    // inside it. This is the bug the trailing-separator check exists for.
    expect(checkEntryPath(root, '../quarantine-scan-abc-evil/x.js')).toMatchObject({
      ok: false,
      reason: 'PATH_ESCAPE',
    });
  });

  it('accepts ordinary nested paths', () => {
    expect(checkEntryPath(root, 'package/index.js')).toMatchObject({
      ok: true,
      relative: 'package/index.js',
    });
    // Interior traversal that stays inside is fine once resolved.
    expect(checkEntryPath(root, 'package/lib/../index.js')).toMatchObject({
      ok: true,
      relative: 'package/index.js',
    });
  });

  it('rejects a path deeper than MAX_DEPTH', () => {
    const deep = Array.from({ length: MAX_DEPTH + 2 }, (_, i) => `d${i}`).join('/');
    expect(checkEntryPath(root, `${deep}/file.js`)).toMatchObject({
      ok: false,
      reason: 'TOO_DEEP',
    });
  });

  it('accepts a path exactly at MAX_DEPTH', () => {
    const atLimit = Array.from({ length: MAX_DEPTH }, (_, i) => `d${i}`).join('/');
    expect(checkEntryPath(root, atLimit).ok).toBe(true);
  });
});

describe('extractTarball — zip-slip in a real archive', () => {
  it('writes nothing outside the root and reports the rejection', async () => {
    const root = await scratch();
    const tarball = buildTarGz([
      { path: 'package/index.js', content: 'module.exports = 1;\n' },
      { path: '../escaped.js', content: 'owned' },
      { path: 'package/../../escaped2.js', content: 'owned' },
      { path: '/etc/passwd', content: 'owned' },
    ]);

    const result = await extractTarball(tarball, root);

    expect(result.files.map((f) => f.path)).toEqual(['index.js']);
    expect(result.rejected).toHaveLength(3);
    expect(result.rejected.map((r) => r.reason).sort()).toEqual([
      'ABSOLUTE_PATH',
      'PATH_ESCAPE',
      'PATH_ESCAPE',
    ]);

    // Nothing landed outside the root.
    expect(await walk(root)).toEqual(['package/index.js']);
    expect(existsSync(path.join(path.dirname(root), 'escaped.js'))).toBe(false);
    expect(existsSync(path.join(path.dirname(root), 'escaped2.js'))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Bombs
// ---------------------------------------------------------------------------

describe('extractTarball — entry-count bomb', () => {
  it('aborts past MAX_ENTRIES', async () => {
    const root = await scratch();
    const entries: FakeEntry[] = Array.from({ length: MAX_ENTRIES + 5 }, (_, i) => ({
      path: `package/f${i}.js`,
      content: 'x',
    }));

    await expect(extractTarball(buildTarGz(entries), root)).rejects.toThrow(/more than/i);
  });

  it('accepts an archive exactly at the limit', async () => {
    const root = await scratch();
    const entries: FakeEntry[] = Array.from({ length: MAX_ENTRIES }, (_, i) => ({
      path: `package/f${i}.js`,
      content: 'x',
    }));

    const result = await extractTarball(buildTarGz(entries), root);
    expect(result.entriesSeen).toBe(MAX_ENTRIES);
  });
});

describe('extractTarball — per-file size bomb', () => {
  it('skips a file whose header declares more than MAX_FILE_BYTES', async () => {
    const root = await scratch();
    const tarball = buildTarGz([
      { path: 'package/ok.js', content: 'fine' },
      { path: 'package/huge.bin', content: 'x', declaredSize: MAX_FILE_BYTES + 1 },
    ]);

    const result = await extractTarball(tarball, root).catch((error: Error) => error);

    // Either it is rejected by header, or the truncated read aborts. Both are
    // safe; what must never happen is a >10MB file on disk.
    if (result instanceof Error) {
      expect(result.message).toMatch(/limit|read/i);
    } else {
      expect(result.rejected.some((r) => r.reason === 'FILE_TOO_LARGE')).toBe(true);
      expect(result.files.every((f) => f.size <= MAX_FILE_BYTES)).toBe(true);
    }

    for (const relative of await walk(root)) {
      const info = await stat(path.join(root, relative));
      expect(info.size).toBeLessThanOrEqual(MAX_FILE_BYTES);
    }
  });

  it('catches a header that under-reports the real size', async () => {
    const root = await scratch();
    // Declare 10 bytes, ship 2MB. Bound 3 passes on the header; the streaming
    // cap is what has to catch this.
    const real = Buffer.alloc(2 * 1024 * 1024, 0x41);
    const tarball = buildTarGz([{ path: 'package/liar.js', content: real, declaredSize: 10 }]);

    const result = await extractTarball(tarball, root).catch((error: Error) => error);

    if (!(result instanceof Error)) {
      // If the parser honoured the declared size, only 10 bytes were read —
      // which is also safe. The invariant is that nothing oversized is stored.
      expect(result.files.every((f) => f.size <= MAX_FILE_BYTES)).toBe(true);
    }
    for (const relative of await walk(root)) {
      const info = await stat(path.join(root, relative));
      expect(info.size).toBeLessThanOrEqual(MAX_FILE_BYTES);
    }
  });
});

describe('extractTarball — total size bomb', () => {
  it('aborts when the archive expands past MAX_TOTAL_BYTES', async () => {
    const root = await scratch();
    // 12 entries of 5MB each = 60MB > 50MB, each individually under the
    // per-file cap, so only the running total can catch it. The content is
    // incompressible so that node-tar's decompression-ratio guard does not
    // fire first — this test is specifically about our own byte counter.
    const entries: FakeEntry[] = Array.from({ length: 12 }, (_, i) => ({
      path: `package/blob${i}.bin`,
      content: incompressible(5 * 1024 * 1024, i),
    }));

    await expect(extractTarball(buildTarGz(entries), root)).rejects.toThrow(/beyond|limit/i);

    // Critically: nothing was written, because writes happen only after every
    // bound has passed.
    expect(await walk(root)).toEqual([]);
  });
});

describe('extractTarball — gzip bomb', () => {
  it('refuses an archive with an implausible decompression ratio', async () => {
    const root = await scratch();
    // 60MB of a single repeated byte compresses about 1000:1, which trips
    // node-tar's own ratio ceiling at the gunzip stage, before any entry is
    // seen. That layer is part of the defence and is asserted here.
    const chunk = Buffer.alloc(5 * 1024 * 1024, 0x42);
    const entries: FakeEntry[] = Array.from({ length: 12 }, (_, i) => ({
      path: `package/blob${i}.bin`,
      content: chunk,
    }));

    await expect(extractTarball(buildTarGz(entries), root)).rejects.toThrow(
      /decompresses to an implausible/i,
    );
    expect(await walk(root)).toEqual([]);
  });
});

describe('extractTarball — depth bomb', () => {
  it('rejects entries nested past MAX_DEPTH', async () => {
    const root = await scratch();
    const deep = Array.from({ length: MAX_DEPTH + 3 }, (_, i) => `d${i}`).join('/');
    const tarball = buildTarGz([
      { path: 'package/shallow.js', content: 'ok' },
      { path: `${deep}/deep.js`, content: 'nope' },
    ]);

    const result = await extractTarball(tarball, root);
    expect(result.files.map((f) => f.path)).toEqual(['shallow.js']);
    expect(result.rejected).toContainEqual({ path: `${deep}/deep.js`, reason: 'TOO_DEEP' });
  });
});

// ---------------------------------------------------------------------------
// Well-formed archives
// ---------------------------------------------------------------------------

describe('extractTarball — ordinary package', () => {
  it('extracts, strips the prefix, hashes and sniffs', async () => {
    const root = await scratch();
    const tarball = await buildRealTarGz({
      'package/package.json': '{"name":"demo","version":"1.0.0"}',
      'package/index.js': 'export const x = 1;\n',
      'package/lib/util.js': 'export const y = 2;\n',
    });

    const result = await extractTarball(tarball, root);
    const paths = result.files.map((f) => f.path).sort();

    expect(paths).toEqual(['index.js', 'lib/util.js', 'package.json']);
    expect(result.totalBytes).toBeGreaterThan(0);

    const indexFile = result.files.find((f) => f.path === 'index.js');
    expect(indexFile?.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(indexFile?.isBinary).toBe(false);
  });

  it('detects a binary file by content, not extension', async () => {
    const root = await scratch();
    const binary = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    const tarball = buildTarGz([
      { path: 'package/innocent.js', content: binary },
      { path: 'package/real.js', content: 'const a = 1;\n' },
    ]);

    const result = await extractTarball(tarball, root);
    expect(result.files.find((f) => f.path === 'innocent.js')?.isBinary).toBe(true);
    expect(result.files.find((f) => f.path === 'real.js')?.isBinary).toBe(false);
  });
});

describe('stripArchivePrefix', () => {
  it('drops the leading wrapper directory', () => {
    expect(stripArchivePrefix('package/index.js')).toBe('index.js');
    expect(stripArchivePrefix('demo-1.0.0/setup.py')).toBe('setup.py');
    expect(stripArchivePrefix('package/lib/deep/file.js')).toBe('lib/deep/file.js');
  });

  it('leaves a bare filename alone', () => {
    expect(stripArchivePrefix('README.md')).toBe('README.md');
  });
});

describe('looksBinary', () => {
  it('treats a NUL byte as binary', () => {
    expect(looksBinary(Buffer.from([0x61, 0x00, 0x62]))).toBe(true);
  });

  it('treats ordinary source as text', () => {
    expect(looksBinary(Buffer.from('function add(a, b) {\n  return a + b;\n}\n'))).toBe(false);
  });

  it('treats UTF-8 prose as text', () => {
    expect(looksBinary(Buffer.from('const greeting = "hello";\n'.repeat(20)))).toBe(false);
  });

  it('treats an empty buffer as text', () => {
    expect(looksBinary(Buffer.alloc(0))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Temp directory lifecycle
// ---------------------------------------------------------------------------

describe('withScanDirectory', () => {
  it('removes the directory after a successful run', async () => {
    let captured = '';
    await withScanDirectory(async (root) => {
      captured = root;
      expect(existsSync(root)).toBe(true);
    });
    expect(existsSync(captured)).toBe(false);
  });

  it('removes the directory when the body throws', async () => {
    let captured = '';
    await expect(
      withScanDirectory(async (root) => {
        captured = root;
        throw new Error('analysis exploded');
      }),
    ).rejects.toThrow('analysis exploded');

    expect(captured).not.toBe('');
    expect(existsSync(captured)).toBe(false);
  });

  it('removes the directory even when it holds extracted content', async () => {
    let captured = '';
    await expect(
      withScanDirectory(async (root) => {
        captured = root;
        await extractTarball(buildTarGz([{ path: 'package/a.js', content: 'x' }]), root);
        expect(existsSync(path.join(root, 'package/a.js'))).toBe(true);
        throw new Error('boom after extraction');
      }),
    ).rejects.toThrow('boom after extraction');

    expect(existsSync(captured)).toBe(false);
  });

  it('propagates the body result', async () => {
    await expect(withScanDirectory(async () => 42)).resolves.toBe(42);
  });
});
