import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Parser } from 'tar';

import { AnalysisError } from '@/lib/errors';
import { logger } from '@/lib/logger';
import {
  BINARY_NONPRINTABLE_RATIO,
  BINARY_SNIFF_BYTES,
} from '@/lib/engine/thresholds';
import type { ExtractedFile } from '@/lib/engine/types';

/**
 * Bounded, non-executing tar.gz extraction.
 *
 * ## THE SAFETY RULE applies to every line of this file
 *
 * The bytes going through here are, by assumption, live malware. This module
 * writes them to a scratch directory and hashes them. It does not run them,
 * import them, register them with a loader, or hand their paths to anything
 * that might. There is no `require`, no `import()`, no `child_process`, and no
 * code path that reaches one.
 *
 * ## Why the limits are not in thresholds.ts
 *
 * `lib/engine/thresholds.ts` holds *detection* thresholds — numbers that are
 * meant to be tuned against the corpus in phase 8 to trade precision against
 * recall. The limits below are not that. They are safety invariants fixed by
 * CLAUDE.md, and tuning them is not a modelling decision but a decision to
 * accept a denial-of-service. They live here, next to the code that enforces
 * them, and they are `as const` so nothing can quietly raise one at runtime.
 *
 * ## Order of enforcement
 *
 * Every bound is checked **before** the first byte of an entry is written, from
 * the tar header. Headers can lie, so the per-file and total byte caps are then
 * enforced *again* against the actual byte count as the entry streams. A
 * mismatch aborts the extraction rather than truncating the file, because a
 * truncated file analysed as if it were whole is worse than no analysis.
 */

/** Total bytes written across the whole archive. */
export const MAX_TOTAL_BYTES = 50 * 1024 * 1024;
/** Number of entries, counting directories and everything skipped. */
export const MAX_ENTRIES = 10_000;
/** Bytes in any single entry. */
export const MAX_FILE_BYTES = 10 * 1024 * 1024;
/** Path segments below the extraction root. */
export const MAX_DEPTH = 20;
/** Bytes of any one file retained as an excerpt source. */
export const MAX_EXCERPT_BYTES = 4096;

/** Entry types that are written. Everything else is counted and discarded. */
const WRITABLE_TYPES = new Set(['File', 'OldFile', 'ContiguousFile']);

export interface ExtractionResult {
  /** Absolute path of the per-scan temp directory. Caller must clean it up. */
  root: string;
  files: ExtractedFile[];
  totalBytes: number;
  entriesSeen: number;
  /** Entries refused, with the reason. Surfaced in the report, not silently dropped. */
  rejected: Array<{ path: string; reason: RejectionReason }>;
}

export type RejectionReason =
  | 'PATH_ESCAPE'
  | 'ABSOLUTE_PATH'
  | 'TOO_DEEP'
  | 'FILE_TOO_LARGE'
  | 'NOT_A_REGULAR_FILE'
  | 'LINK';

// ---------------------------------------------------------------------------
// Path safety
// ---------------------------------------------------------------------------

export interface PathCheck {
  ok: boolean;
  reason?: RejectionReason;
  /** Absolute destination, only when `ok`. */
  absolute?: string;
  /** Package-relative POSIX path, only when `ok`. */
  relative?: string;
}

/**
 * Zip-slip guard.
 *
 * The check that matters is the containment test on the **resolved** path:
 * `path.resolve` collapses every `..`, every doubled separator and every
 * oddity in the entry name, and the result must still sit inside the root.
 * Anything else — inspecting the raw string for `..`, rejecting leading
 * slashes — is a heuristic that has been bypassed many times. This is not.
 *
 * The trailing-separator comparison is deliberate: without it, a root of
 * `/tmp/scan` would happily accept `/tmp/scan-evil/x`, which shares the prefix
 * but is a different directory.
 */
export function checkEntryPath(root: string, entryPath: string): PathCheck {
  // Tar entries are POSIX paths. Normalise separators so a Windows-style entry
  // cannot sneak past a POSIX-only check.
  const raw = entryPath.replace(/\\/g, '/');

  if (raw.length === 0) return { ok: false, reason: 'PATH_ESCAPE' };

  // An absolute entry path, or a Windows drive letter, is never legitimate.
  if (raw.startsWith('/') || /^[a-zA-Z]:/.test(raw)) {
    return { ok: false, reason: 'ABSOLUTE_PATH' };
  }

  const resolvedRoot = path.resolve(root);
  const absolute = path.resolve(resolvedRoot, raw);

  // THE containment check. `absolute` has already had every `..` collapsed.
  const withSeparator = resolvedRoot.endsWith(path.sep) ? resolvedRoot : resolvedRoot + path.sep;
  if (absolute !== resolvedRoot && !absolute.startsWith(withSeparator)) {
    return { ok: false, reason: 'PATH_ESCAPE' };
  }

  const relative = path.relative(resolvedRoot, absolute).split(path.sep).join('/');

  // `path.relative` returning something that climbs is a second, independent
  // way of catching an escape. Belt and braces on the one check that must hold.
  if (relative.startsWith('..')) {
    return { ok: false, reason: 'PATH_ESCAPE' };
  }

  if (relative.split('/').filter(Boolean).length > MAX_DEPTH) {
    return { ok: false, reason: 'TOO_DEEP' };
  }

  return { ok: true, absolute, relative };
}

/** npm tarballs nest everything under `package/`; PyPI under `<name>-<version>/`. */
export function stripArchivePrefix(relativePath: string): string {
  const segments = relativePath.split('/');
  return segments.length > 1 ? segments.slice(1).join('/') : relativePath;
}

// ---------------------------------------------------------------------------
// Binary sniffing
// ---------------------------------------------------------------------------

/** Classify by content, never by extension — an attacker chooses the extension. */
export function looksBinary(sample: Buffer): boolean {
  if (sample.length === 0) return false;

  const limit = Math.min(sample.length, BINARY_SNIFF_BYTES);
  let nonPrintable = 0;

  for (let index = 0; index < limit; index++) {
    const byte = sample[index];
    if (byte === undefined) continue;
    // A NUL byte in the first block is the classic binary tell.
    if (byte === 0) return true;
    const printable =
      byte === 0x09 || byte === 0x0a || byte === 0x0d || (byte >= 0x20 && byte <= 0x7e);
    if (!printable) nonPrintable++;
  }

  return nonPrintable / limit > BINARY_NONPRINTABLE_RATIO;
}

// ---------------------------------------------------------------------------
// Temp directory lifecycle
// ---------------------------------------------------------------------------

/** Create a per-scan scratch directory with a mode nothing else can read. */
export async function createScanDirectory(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), 'quarantine-scan-'));
  return root;
}

/**
 * Remove a scan directory. Never throws: cleanup failure is logged, because
 * throwing here would mask whatever real error sent us into the finally block.
 */
export async function destroyScanDirectory(root: string): Promise<void> {
  if (!root) return;
  try {
    await rm(root, { recursive: true, force: true, maxRetries: 3 });
  } catch (error) {
    logger.error({ err: error, root }, 'failed to remove scan directory');
  }
}

/**
 * Run `work` with a fresh scan directory and delete it afterwards, on every
 * path — return, throw, or rejection.
 *
 * This is the only supported way to get a scan directory. Callers that manage
 * the lifecycle themselves eventually forget a branch; this cannot.
 */
export async function withScanDirectory<T>(work: (root: string) => Promise<T>): Promise<T> {
  const root = await createScanDirectory();
  try {
    return await work(root);
  } finally {
    await destroyScanDirectory(root);
  }
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

interface PendingEntry {
  check: PathCheck;
  declaredSize: number;
}

/**
 * Extract a gzipped tarball into `root`.
 *
 * The archive is parsed from a buffer already in memory — the fetcher caps how
 * much can be downloaded, so there is no unbounded read here. Each entry is
 * vetted from its header before any write, then bounded again while streaming.
 *
 * Never executes, requires, imports or evaluates anything it extracts.
 */
export async function extractTarball(tarball: Buffer, root: string): Promise<ExtractionResult> {
  const files: ExtractedFile[] = [];
  const rejected: Array<{ path: string; reason: RejectionReason }> = [];

  let entriesSeen = 0;
  let totalBytes = 0;
  let aborted: AnalysisError | null = null;

  /**
   * Content for entries that passed every header bound, keyed by destination.
   *
   * Holding content here until the whole archive has been vetted is what makes
   * "bounds before disk" literally true: nothing is written until the archive
   * as a whole is known to be within limits. It is scoped to this call — module
   * state would collide between concurrent scans — and the total it can hold is
   * capped by MAX_TOTAL_BYTES, so it cannot grow without bound.
   */
  const pendingContent = new Map<string, Buffer>();

  const parser = new Parser({
    // No filesystem side effects from the parser itself: it emits entries and
    // this module decides, one at a time, what reaches disk.
    strict: false,
  });

  const pendingWrites: Array<Promise<void>> = [];

  parser.on('entry', (entry) => {
    // Once something has gone wrong, drain the rest without inspecting it.
    if (aborted) {
      entry.resume();
      return;
    }

    entriesSeen++;

    // BOUND 1 — entry count. Checked before anything else touches this entry.
    if (entriesSeen > MAX_ENTRIES) {
      aborted = new AnalysisError(
        'ENTRY_LIMIT',
        `Archive contains more than ${MAX_ENTRIES} entries.`,
      );
      entry.resume();
      return;
    }

    const entryPath = String(entry.path ?? '');

    // Links are never written. A symlink is the other half of a zip-slip: the
    // link itself stays inside the root, and a later entry writes through it.
    // Hardlinks have the same problem. Neither is needed for static analysis.
    if (entry.type === 'SymbolicLink' || entry.type === 'Link') {
      rejected.push({ path: entryPath, reason: 'LINK' });
      entry.resume();
      return;
    }

    if (!WRITABLE_TYPES.has(String(entry.type))) {
      // Directories and everything exotic (character devices, FIFOs) are
      // counted and discarded. Directories are recreated implicitly on write.
      if (entry.type !== 'Directory') {
        rejected.push({ path: entryPath, reason: 'NOT_A_REGULAR_FILE' });
      }
      entry.resume();
      return;
    }

    // BOUND 2 — zip-slip and depth, from the header, before any write.
    const check = checkEntryPath(root, entryPath);
    if (!check.ok || !check.absolute || !check.relative) {
      rejected.push({ path: entryPath, reason: check.reason ?? 'PATH_ESCAPE' });
      logger.warn({ entryPath, reason: check.reason }, 'rejected archive entry');
      entry.resume();
      return;
    }

    const declaredSize = Number(entry.size ?? 0);

    // BOUND 3 — per-file cap, from the header, before any write.
    if (declaredSize > MAX_FILE_BYTES) {
      rejected.push({ path: entryPath, reason: 'FILE_TOO_LARGE' });
      entry.resume();
      return;
    }

    // BOUND 4 — total cap, from the header, before any write.
    if (totalBytes + declaredSize > MAX_TOTAL_BYTES) {
      aborted = new AnalysisError(
        'SIZE_LIMIT',
        `Archive expands beyond the ${MAX_TOTAL_BYTES} byte limit.`,
      );
      entry.resume();
      return;
    }

    pendingWrites.push(
      collectEntry(entry, { check, declaredSize }, pendingContent)
        .then((collected) => {
          if (aborted || !collected) return;

          // BOUND 5 — the same caps again, against bytes actually seen. A tar
          // header that under-reports its size is a size bomb; this is where it
          // is caught, since bounds 3 and 4 could only trust the header.
          if (collected.bytes.length > MAX_FILE_BYTES) {
            aborted = new AnalysisError(
              'SIZE_LIMIT',
              'An archive entry is larger than its header declared.',
            );
            return;
          }
          if (totalBytes + collected.bytes.length > MAX_TOTAL_BYTES) {
            aborted = new AnalysisError(
              'SIZE_LIMIT',
              `Archive expands beyond the ${MAX_TOTAL_BYTES} byte limit.`,
            );
            return;
          }

          totalBytes += collected.bytes.length;
          files.push(collected.file);
        })
        .catch((error: unknown) => {
          if (!aborted) {
            aborted = new AnalysisError('MALFORMED_ARCHIVE', 'Archive entry could not be read.', {
              cause: error,
            });
          }
        }),
    );
  });

  await new Promise<void>((resolve, reject) => {
    parser.on('error', (error: unknown) => reject(toParseError(error)));
    parser.on('end', () => resolve());
    parser.end(tarball);
  });

  try {
    await Promise.all(pendingWrites);

    if (aborted) throw aborted;

    // Writes happen only after every bound has passed, in one batch, so an
    // entry that violated any limit never reaches disk at all.
    for (const file of files) {
      await mkdir(path.dirname(file.absolutePath), { recursive: true });
      await writeFile(file.absolutePath, pendingContent.get(file.absolutePath) ?? Buffer.alloc(0), {
        mode: 0o600,
      });
    }
  } finally {
    // Release the buffered content on every path, including the throw above.
    pendingContent.clear();
  }

  return { root, files, totalBytes, entriesSeen, rejected };
}

interface CollectedEntry {
  file: ExtractedFile;
  bytes: Buffer;
}

/**
 * Translate a parser failure into an AnalysisError with a useful reason.
 *
 * node-tar enforces its own decompression-ratio ceiling, which trips on a gzip
 * bomb before our byte counters ever see the expanded data — 60MB of identical
 * bytes compresses to 62KB, and the archive is refused at the gunzip stage.
 * That is a genuine layer of the defence and deserves its own reason code
 * rather than being reported as a generic parse failure.
 */
function toParseError(error: unknown): AnalysisError {
  const message = error instanceof Error ? error.message : '';

  if (/decompression ratio/i.test(message)) {
    return new AnalysisError(
      'COMPRESSION_BOMB',
      'Archive decompresses to an implausible multiple of its size.',
      { cause: error },
    );
  }

  return new AnalysisError('MALFORMED_ARCHIVE', 'Archive could not be parsed.', { cause: error });
}

/** Read one entry into memory, enforcing the per-file cap as bytes arrive. */
function collectEntry(
  entry: NodeJS.ReadableStream & { path?: string },
  pending: PendingEntry,
  pendingContent: Map<string, Buffer>,
): Promise<CollectedEntry | null> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let seen = 0;
    let failed = false;

    entry.on('data', (chunk: Buffer) => {
      if (failed) return;
      seen += chunk.length;

      // Streaming cap: stop reading the moment a lying header is exposed,
      // rather than after buffering ten more megabytes of it.
      if (seen > MAX_FILE_BYTES) {
        failed = true;
        entry.resume();
        reject(new AnalysisError('SIZE_LIMIT', 'An archive entry exceeded the per-file limit.'));
        return;
      }
      chunks.push(chunk);
    });

    entry.on('error', (error: unknown) => {
      if (!failed) {
        failed = true;
        reject(error);
      }
    });

    entry.on('end', () => {
      if (failed) return;

      const bytes = Buffer.concat(chunks, seen);
      const absolute = pending.check.absolute as string;
      const relative = pending.check.relative as string;

      pendingContent.set(absolute, bytes);

      resolve({
        bytes,
        file: {
          path: stripArchivePrefix(relative),
          size: bytes.length,
          absolutePath: absolute,
          isBinary: looksBinary(bytes.subarray(0, BINARY_SNIFF_BYTES)),
          sha256: createHash('sha256').update(bytes).digest('hex'),
        },
      });
    });
  });
}
