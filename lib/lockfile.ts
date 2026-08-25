/**
 * Lockfile parsing.
 *
 * A lockfile is untrusted input like everything else here: it arrives from a
 * browser upload, it names packages an attacker may control, and it can be
 * enormous. So this parser is pure, allocation-bounded, and does exactly one
 * thing — turn text into a list of `{ name, version }` coordinates. It resolves
 * nothing, fetches nothing, and never touches the filesystem.
 *
 * Supported: npm `package-lock.json` (v1 dependency tree and v2/v3 `packages`
 * map) and classic `yarn.lock`. `pnpm-lock.yaml` is not supported — parsing YAML
 * safely would mean pulling in a YAML parser for one format, and pnpm users can
 * export an npm lockfile. An unrecognised file is reported as such rather than
 * being guessed at.
 */

export type LockfileKind = 'package-lock' | 'yarn' | 'unknown';

export interface LockfileEntry {
  name: string;
  version: string;
  /** True when the lockfile marks this as a direct dependency of the root project. */
  direct: boolean;
}

export interface ParsedLockfile {
  kind: LockfileKind;
  entries: LockfileEntry[];
  /** Distinct coordinates found before the cap was applied. */
  found: number;
  /** True when `found` exceeded `maxEntries` and the list was cut. */
  truncated: boolean;
}

export interface ParseOptions {
  /** Hard cap on returned coordinates. */
  maxEntries?: number;
}

export const MAX_LOCKFILE_BYTES = 8 * 1024 * 1024;
export const DEFAULT_MAX_ENTRIES = 500;

/** Same shape npm allows, checked here so a lockfile cannot smuggle a path. */
const NAME_PATTERN = /^(?:@[a-z0-9\-*~][a-z0-9\-*._~]*\/)?[a-z0-9\-~][a-z0-9\-._~]*$/;
const VERSION_PATTERN = /^[0-9][0-9a-zA-Z.\-+]*$/;

function isPlausible(name: string, version: string): boolean {
  return (
    name.length > 0 &&
    name.length <= 214 &&
    NAME_PATTERN.test(name) &&
    version.length > 0 &&
    version.length <= 64 &&
    VERSION_PATTERN.test(version)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * `node_modules/foo/node_modules/@scope/bar` -> `@scope/bar`.
 * Anything outside node_modules (a workspace package) has no registry artefact
 * to analyse and is skipped.
 */
function nameFromPackagePath(path: string): string | null {
  const marker = 'node_modules/';
  const index = path.lastIndexOf(marker);
  if (index === -1) return null;
  const name = path.slice(index + marker.length);
  return name.length > 0 ? name : null;
}

function parsePackageLock(document: Record<string, unknown>): LockfileEntry[] {
  const entries = new Map<string, LockfileEntry>();

  const add = (name: string, version: unknown, direct: boolean): void => {
    if (typeof version !== 'string') return;
    if (!isPlausible(name, version)) return;
    const key = `${name}@${version}`;
    const existing = entries.get(key);
    if (existing) {
      if (direct) existing.direct = true;
      return;
    }
    entries.set(key, { name, version, direct });
  };

  // Lockfile v2 / v3: a flat map keyed by install path.
  const packages = document.packages;
  if (isRecord(packages)) {
    const rootDependencies = new Set<string>();
    const root = packages[''];
    if (isRecord(root)) {
      for (const field of ['dependencies', 'devDependencies', 'optionalDependencies'] as const) {
        const block = root[field];
        if (isRecord(block)) {
          for (const name of Object.keys(block)) rootDependencies.add(name);
        }
      }
    }

    for (const [path, value] of Object.entries(packages)) {
      if (path === '' || !isRecord(value)) continue;
      if (value.link === true) continue;
      const name = typeof value.name === 'string' ? value.name : nameFromPackagePath(path);
      if (!name) continue;
      add(name, value.version, rootDependencies.has(name));
    }
  }

  // Lockfile v1: a nested tree under `dependencies`.
  const walk = (block: unknown, depth: number, direct: boolean): void => {
    if (depth > 20 || !isRecord(block)) return;
    for (const [name, value] of Object.entries(block)) {
      if (!isRecord(value)) continue;
      add(name, value.version, direct);
      walk(value.dependencies, depth + 1, false);
    }
  };
  walk(document.dependencies, 0, true);

  return [...entries.values()];
}

/**
 * Classic yarn.lock. The format is a small indentation-based dialect, not YAML:
 * a descriptor line naming one or more specifiers, then an indented block whose
 * `version` field carries the resolved version.
 */
function parseYarnLock(content: string): LockfileEntry[] {
  const entries = new Map<string, LockfileEntry>();
  const lines = content.split(/\r\n?|\n/);

  let pendingNames: string[] = [];

  for (const line of lines) {
    if (line.length === 0 || line.startsWith('#')) continue;

    if (!/^\s/.test(line)) {
      pendingNames = [];
      const descriptor = line.replace(/:\s*$/, '');
      for (const raw of descriptor.split(',')) {
        const specifier = raw.trim().replace(/^"|"$/g, '');
        if (specifier.length === 0) continue;
        // Split on the last @, which separates name from range — a scoped name
        // starts with one of its own.
        const at = specifier.lastIndexOf('@');
        if (at <= 0) continue;
        pendingNames.push(specifier.slice(0, at));
      }
      continue;
    }

    const match = /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (!match || pendingNames.length === 0) continue;

    const version = match[1] ?? '';
    for (const name of pendingNames) {
      if (!isPlausible(name, version)) continue;
      const key = `${name}@${version}`;
      if (!entries.has(key)) entries.set(key, { name, version, direct: false });
    }
    pendingNames = [];
  }

  return [...entries.values()];
}

/** Parse a lockfile's text. Never throws on malformed input — it reports `unknown`. */
export function parseLockfile(
  filename: string,
  content: string,
  options: ParseOptions = {},
): ParsedLockfile {
  const maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
  const lower = filename.toLowerCase();

  let kind: LockfileKind = 'unknown';
  let entries: LockfileEntry[] = [];

  const looksJson = content.trimStart().startsWith('{');

  if (lower.endsWith('.json') || looksJson) {
    try {
      const parsed: unknown = JSON.parse(content);
      if (isRecord(parsed) && (isRecord(parsed.packages) || isRecord(parsed.dependencies))) {
        kind = 'package-lock';
        entries = parsePackageLock(parsed);
      }
    } catch {
      // Malformed JSON is an unknown file, not an exception the caller has to
      // handle: the user gets "we could not read that", which is the truth.
    }
  }

  if (kind === 'unknown' && (lower.endsWith('yarn.lock') || content.includes('# yarn lockfile'))) {
    kind = 'yarn';
    entries = parseYarnLock(content);
  }

  entries.sort((a, b) =>
    a.name === b.name ? a.version.localeCompare(b.version) : a.name.localeCompare(b.name),
  );

  const found = entries.length;
  return {
    kind,
    entries: entries.slice(0, maxEntries),
    found,
    truncated: found > maxEntries,
  };
}
