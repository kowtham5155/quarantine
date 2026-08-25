import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { looksBinary } from '@/lib/engine/extract';
import { deriveContextBucket } from '@/lib/engine/signals/capability';
import { hashNormalised } from '@/lib/engine/signals/provenance';
import type {
  AnalysisContext,
  ExtractedFile,
  Maintainer,
  PackageArtifact,
  PackageMetadata,
  ReleaseRecord,
  RepositorySnapshot,
  RuleDefinition,
  Signal,
} from '@/lib/engine/types';

/**
 * Fixture builder for the signal modules.
 *
 * ## What a fixture is here
 *
 * Signal modules read a `PackageArtifact`: registry metadata plus a list of
 * files that exist on disk. So the fixtures write real files to a real
 * temporary directory — the modules open them with `readFile` and parse the
 * bytes, and stubbing that away would test a mock instead of the analyser.
 *
 * ## SAFETY
 *
 * Every fixture in this suite is a hand-written string in a test file. None of
 * it is downloaded, and none of it is ever executed, required, imported or
 * evaluated — the modules under test parse it and read it, and the assertions
 * are about signals, not about behaviour. The strings *look* like malware on
 * purpose: that is the input the engine is built to recognise.
 *
 * Every fixture directory is removed by `cleanupFixtures()` in an `afterEach`.
 */

const created: string[] = [];

/** Remove every fixture directory made since the last call. Use in `afterEach`. */
export async function cleanupFixtures(): Promise<void> {
  const roots = created.splice(0, created.length);
  await Promise.all(roots.map((root) => rm(root, { recursive: true, force: true })));
}

export interface FixtureFile {
  path: string;
  content: string | Buffer;
}

export interface FixtureOptions {
  name?: string;
  version?: string;
  ecosystem?: 'NPM' | 'PYPI';
  files?: FixtureFile[];
  scripts?: Record<string, string>;
  keywords?: string[];
  description?: string | null;
  dependencies?: Record<string, string>;
  maintainers?: Maintainer[];
  publishedAt?: Date | null;
  releaseHistory?: ReleaseRecord[];
  weeklyDownloads?: number | null;
  dependentCount?: number | null;
  repositoryUrl?: string | null;
  repository?: RepositorySnapshot;
  /** Rule ids the fixture should present as enabled. Defaults to every rule. */
  rules?: Map<string, RuleDefinition>;
  deadlineMs?: number;
}

export function maintainer(name: string, overrides: Partial<Maintainer> = {}): Maintainer {
  return {
    name,
    accountCreatedAt: null,
    packageCount: null,
    firstSeenAt: null,
    ...overrides,
  };
}

/** Every rule enabled, with a weight of 10, unless a test says otherwise. */
export function allRulesEnabled(weight = 10): Map<string, RuleDefinition> {
  const families: Record<string, { family: RuleDefinition['family']; count: number }> = {
    INS: { family: 'INSTALL', count: 7 },
    OBF: { family: 'OBFUSCATION', count: 7 },
    CAP: { family: 'CAPABILITY', count: 9 },
    TYP: { family: 'TYPOSQUAT', count: 6 },
    MNT: { family: 'MAINTAINER', count: 6 },
    PRV: { family: 'PROVENANCE', count: 6 },
  };

  const rules = new Map<string, RuleDefinition>();
  for (const [prefix, { family, count }] of Object.entries(families)) {
    for (let index = 1; index <= count; index++) {
      const ruleId = `Q-${prefix}-${String(index).padStart(3, '0')}`;
      rules.set(ruleId, {
        ruleId,
        family,
        name: ruleId,
        description: ruleId,
        severity: 'MEDIUM',
        baseWeight: weight,
        enabled: true,
      });
    }
  }
  return rules;
}

/**
 * Write a package to a temp directory and build the context the modules take.
 *
 * The returned context is exactly what the orchestrator would assemble, minus
 * the network: metadata is supplied by the test rather than fetched, and the
 * files are on disk rather than extracted from a tarball.
 */
export async function buildContext(options: FixtureOptions = {}): Promise<AnalysisContext> {
  const root = await mkdtemp(path.join(tmpdir(), 'quarantine-fixture-'));
  created.push(root);

  const files: ExtractedFile[] = [];
  let totalBytes = 0;

  for (const file of options.files ?? []) {
    const bytes = Buffer.isBuffer(file.content) ? file.content : Buffer.from(file.content, 'utf8');
    const absolutePath = path.join(root, file.path);
    await mkdir(path.dirname(absolutePath), { recursive: true });
    await writeFile(absolutePath, bytes);

    totalBytes += bytes.length;
    files.push({
      path: file.path,
      size: bytes.length,
      absolutePath,
      isBinary: looksBinary(bytes.subarray(0, 8192)),
      sha256: createHash('sha256').update(bytes).digest('hex'),
    });
  }

  const metadata: PackageMetadata = {
    name: options.name ?? 'fixture-package',
    version: options.version ?? '1.0.0',
    ecosystem: options.ecosystem ?? 'NPM',
    description: options.description === undefined ? 'a fixture' : options.description,
    keywords: options.keywords ?? [],
    license: 'MIT',
    repositoryUrl: options.repositoryUrl ?? null,
    homepage: null,
    scripts: options.scripts ?? {},
    dependencies: options.dependencies ?? {},
    maintainers: options.maintainers ?? [maintainer('fixture-author')],
    publishedAt: options.publishedAt === undefined ? new Date('2026-01-01') : options.publishedAt,
    releaseHistory: options.releaseHistory ?? [],
    weeklyDownloads: options.weeklyDownloads === undefined ? 100 : options.weeklyDownloads,
    dependentCount: options.dependentCount ?? null,
    tarballUrl: 'https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz',
    integrity: null,
    hasProvenanceAttestation: false,
  };

  const artifact: PackageArtifact = {
    metadata,
    files,
    tarballSha256: createHash('sha256').update(root).digest('hex'),
    totalBytes,
    extractionRoot: root,
  };

  return {
    artifact,
    rules: options.rules ?? allRulesEnabled(),
    contextBucket: deriveContextBucket(metadata),
    deadline: Date.now() + (options.deadlineMs ?? 30_000),
    correlationId: 'test',
    ...(options.repository ? { repository: options.repository } : {}),
  };
}

/** The rules that fired, as a set of ids. */
export function firedIds(signals: Signal[]): Set<string> {
  return new Set(signals.filter((signal) => signal.fired).map((signal) => signal.ruleId));
}

/** One signal by id, for assertions about confidence, evidence or skips. */
export function signalFor(signals: Signal[], ruleId: string): Signal {
  const signal = signals.find((candidate) => candidate.ruleId === ruleId);
  if (!signal) throw new Error(`no signal emitted for ${ruleId}`);
  return signal;
}

/** A repository snapshot whose file hashes match the given contents. */
export function snapshotOf(
  contents: Record<string, string>,
  overrides: Partial<RepositorySnapshot> = {},
): RepositorySnapshot {
  const files = new Map<string, string>();
  for (const [filePath, content] of Object.entries(contents)) {
    // Hashed through the provenance comparator's own normaliser, so a change
    // to normalisation cannot leave these fixtures comparing stale digests.
    files.set(filePath, hashNormalised(Buffer.from(content, 'utf8')));
  }

  return {
    host: 'github.com',
    owner: 'acme',
    repo: 'fixture',
    tag: 'v1.0.0',
    files,
    archived: false,
    ...overrides,
  };
}
