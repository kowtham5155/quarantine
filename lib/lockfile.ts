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
  /**
   * Distance from the root project in the declared dependency graph: 0 for a
   * direct dependency, 1 for something a direct dependency pulled in, and so on.
   *
   * This is graph depth, not install depth. npm hoists almost everything to a
   * flat `node_modules`, so the path a package is installed at says nothing
   * about why it is there; the edges declared in the lockfile do.
   */
  depth: number;
  /** Ancestor chain from the root, excluding this package. Empty for a direct dependency. */
  path: string[];
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

interface DependencyGraph {
  entries: Map<string, LockfileEntry>;
  /** name -> names it declares a dependency on. */
  edges: Map<string, Set<string>>;
  /** Names the root project depends on directly. */
  roots: Set<string>;
}

/** Names declared in the dependency blocks of one lockfile node. */
function declaredDependencies(node: Record<string, unknown>): string[] {
  const names: string[] = [];
  for (const field of [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'peerDependencies',
    'requires',
  ] as const) {
    const block = node[field];
    // In lockfile v1 `dependencies` is a nested tree of objects; in v2/v3 and in
    // `requires` it is a name -> range map. Both give the names we need.
    if (isRecord(block)) names.push(...Object.keys(block));
  }
  return names;
}

/**
 * Walk the graph outward from the root, assigning each package the shortest
 * path that reaches it.
 *
 * Breadth-first, so the first path found is the shortest one — which is the
 * path a developer needs to see to remove the dependency. A package the walk
 * never reaches (a hoisted duplicate the lockfile does not link back to
 * anything) is recorded as transitive with an unknown path rather than being
 * given an invented one.
 */
function assignDepths(graph: DependencyGraph): void {
  const seen = new Set<string>();
  let frontier: Array<{ name: string; path: string[] }> = [...graph.roots].map((name) => ({
    name,
    path: [],
  }));
  let depth = 0;

  while (frontier.length > 0 && depth <= 20) {
    const next: Array<{ name: string; path: string[] }> = [];

    for (const node of frontier) {
      if (seen.has(node.name)) continue;
      seen.add(node.name);

      for (const entry of graph.entries.values()) {
        if (entry.name !== node.name) continue;
        entry.depth = depth;
        entry.path = node.path;
        entry.direct = entry.direct || depth === 0;
      }

      for (const child of graph.edges.get(node.name) ?? []) {
        if (seen.has(child)) continue;
        next.push({ name: child, path: [...node.path, node.name] });
      }
    }

    frontier = next;
    depth += 1;
  }

  for (const entry of graph.entries.values()) {
    if (seen.has(entry.name)) continue;
    entry.depth = 1;
    entry.path = [];
  }
}

function parsePackageLock(document: Record<string, unknown>): LockfileEntry[] {
  const graph: DependencyGraph = { entries: new Map(), edges: new Map(), roots: new Set() };

  const add = (name: string, version: unknown, direct: boolean): void => {
    if (typeof version !== 'string') return;
    if (!isPlausible(name, version)) return;
    const key = `${name}@${version}`;
    const existing = graph.entries.get(key);
    if (existing) {
      if (direct) existing.direct = true;
      return;
    }
    graph.entries.set(key, { name, version, direct, depth: direct ? 0 : 1, path: [] });
  };

  const link = (from: string, to: string[]): void => {
    const set = graph.edges.get(from) ?? new Set<string>();
    for (const name of to) set.add(name);
    graph.edges.set(from, set);
  };

  // Lockfile v2 / v3: a flat map keyed by install path.
  const packages = document.packages;
  if (isRecord(packages)) {
    const root = packages[''];
    if (isRecord(root)) {
      for (const name of declaredDependencies(root)) graph.roots.add(name);
    }

    for (const [path, value] of Object.entries(packages)) {
      if (path === '' || !isRecord(value)) continue;
      if (value.link === true) continue;
      const name = typeof value.name === 'string' ? value.name : nameFromPackagePath(path);
      if (!name) continue;
      add(name, value.version, graph.roots.has(name));
      link(name, declaredDependencies(value));
    }
  }

  // Lockfile v1: a nested tree under `dependencies`.
  const walk = (block: unknown, level: number, direct: boolean, parent: string | null): void => {
    if (level > 20 || !isRecord(block)) return;
    for (const [name, value] of Object.entries(block)) {
      if (!isRecord(value)) continue;
      add(name, value.version, direct);
      if (direct) graph.roots.add(name);
      if (parent) link(parent, [name]);
      link(name, declaredDependencies(value));
      walk(value.dependencies, level + 1, false, name);
    }
  };
  walk(document.dependencies, 0, true, null);

  assignDepths(graph);

  return [...graph.entries.values()];
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
      // yarn.lock's own dependency blocks are not parsed, so there is no graph
      // to walk here: every entry is reported as transitive with an unknown
      // path, which is less than package-lock gives but is not a guess.
      if (!entries.has(key)) entries.set(key, { name, version, direct: false, depth: 1, path: [] });
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
