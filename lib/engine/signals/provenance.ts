import { createHash } from 'node:crypto';

import {
  BINARY_BLOB_MIN_BYTES,
  PROVENANCE_EXTRA_FILE_TOLERANCE,
  PROVENANCE_MODIFIED_RATIO,
} from '@/lib/engine/thresholds';
import type { AnalysisContext, FamilyResult, RepositorySnapshot } from '@/lib/engine/types';
import { metadataEvidence, evidence, runFamily } from '@/lib/engine/signals/helpers';

/**
 * FAMILY 6 — provenance. The highest-value family in the engine.
 *
 * The question this family answers is the one that actually catches a supply
 * chain attack: **does the published tarball match the source anyone reviewed?**
 *
 * event-stream 3.3.6 is the canonical case. The malicious code was in the
 * tarball on npm and was never in the GitHub repository. Every reviewer looking
 * at the source saw clean code; every machine installing the package got the
 * payload. No amount of reading the repository would have found it, and no CVE
 * database had it, because it was not a vulnerability — it was a different
 * artefact wearing the same name.
 *
 * ## Degrading honestly
 *
 * This family fails constantly and for boring reasons: no repository field, a
 * repository that 404s, a tag naming convention nobody guessed, a monorepo
 * where the package lives three directories down. Every one of those is a
 * *different outcome from divergence*, and conflating them is how a provenance
 * checker becomes a false-positive generator that everyone turns off.
 *
 *   NO_REPO           — the package never claimed a source. Q-PRV-001 fires.
 *   REPO_UNREACHABLE  — it claimed one we could not read. Q-PRV-002 fires.
 *   NO_TAG_MATCH      — we found the repo but not this version. Comparison
 *                       rules are SKIPPED, not failed.
 *   divergent         — we compared and they differ. Q-PRV-003/004 fire.
 *
 * A skipped comparison lowers overall confidence rather than producing a
 * verdict, which is the correct behaviour: not knowing is not the same as
 * finding nothing.
 */

export const PROVENANCE_RULES = [
  'Q-PRV-001',
  'Q-PRV-002',
  'Q-PRV-003',
  'Q-PRV-004',
  'Q-PRV-005',
  'Q-PRV-006',
] as const;

/**
 * Paths that legitimately exist in a tarball and not in git, or vice versa.
 *
 * Getting this list right is what makes Q-PRV-003 usable. Build output,
 * generated declarations, and packaging metadata are all expected to differ,
 * and treating them as evidence would bury the one file that matters.
 */
const NORMALISE_PATTERNS: RegExp[] = [
  /^node_modules\//,
  /^\.git\//,
  /^\.github\//,
  /^\.circleci\//,
  /^\.vscode\//,
  /^\.idea\//,
  /(?:^|\/)\.DS_Store$/,
  /^(?:dist|build|lib|es|esm|cjs|umd|out|output|types|typings)\//,
  /\.min\.(?:js|css|mjs|cjs)$/,
  /\.map$/,
  /\.d\.ts$/,
  /^(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|npm-shrinkwrap\.json)$/,
  /^(?:\.npmignore|\.gitignore|\.gitattributes|\.editorconfig)$/,
  /^(?:\.eslintrc.*|\.prettierrc.*|eslint\.config\..*|prettier\.config\..*)$/,
  /^(?:tsconfig.*\.json|jsconfig\.json|babel\.config\..*|\.babelrc.*)$/,
  /^(?:rollup|webpack|vite|jest|vitest|karma|gulpfile|Gruntfile)\..*/,
  /^(?:CHANGELOG|CONTRIBUTING|CODE_OF_CONDUCT|SECURITY)\.md$/i,
  /^(?:test|tests|spec|__tests__|__mocks__|examples?|docs?|benchmark)\//,
  /\.(?:test|spec)\.[cm]?[jt]sx?$/,
  /^coverage\//,
  /^\.changeset\//,
];

/** Files whose presence in a tarball but not in source is the actual signal. */
const EXECUTABLE_EXTENSIONS = /\.(?:js|mjs|cjs|jsx|ts|mts|cts|tsx|py|sh|bash|ps1|bat|cmd)$/i;

const BINARY_EXTENSIONS = /\.(?:node|so|dylib|dll|exe|bin|wasm|a|o)$/i;

/** True when a path is expected to differ between a tarball and a source tree. */
export function isNormalisedAway(path: string): boolean {
  return NORMALISE_PATTERNS.some((pattern) => pattern.test(path));
}

export interface TreeComparison {
  /** In the tarball, absent from source, after normalisation. */
  onlyInTarball: string[];
  /** In source, absent from the tarball. Informational, not a signal. */
  onlyInSource: string[];
  /** Present in both with different content hashes. */
  modified: string[];
  /** Present in both with identical content. */
  identical: string[];
  /** Of `onlyInTarball`, those that can execute. This is the dangerous set. */
  executableOnlyInTarball: string[];
}

/**
 * Compare a tarball's file set against a source tree.
 *
 * Both sides are normalised first, so the comparison is between "files a human
 * would have reviewed" and "files that will land on a machine".
 */
export function compareTrees(
  tarballFiles: Array<{ path: string; sha256: string }>,
  sourceFiles: Map<string, string>,
): TreeComparison {
  const onlyInTarball: string[] = [];
  const modified: string[] = [];
  const identical: string[] = [];

  const seen = new Set<string>();

  for (const file of tarballFiles) {
    if (isNormalisedAway(file.path)) continue;
    seen.add(file.path);

    const sourceHash = sourceFiles.get(file.path);
    if (sourceHash === undefined) {
      onlyInTarball.push(file.path);
    } else if (sourceHash !== file.sha256) {
      modified.push(file.path);
    } else {
      identical.push(file.path);
    }
  }

  const onlyInSource: string[] = [];
  for (const path of sourceFiles.keys()) {
    if (isNormalisedAway(path)) continue;
    if (!seen.has(path)) onlyInSource.push(path);
  }

  return {
    onlyInTarball,
    onlyInSource,
    modified,
    identical,
    executableOnlyInTarball: onlyInTarball.filter((path) => EXECUTABLE_EXTENSIONS.test(path)),
  };
}

/** Candidate git tags for a version, in the order they should be tried. */
export function candidateTags(version: string): string[] {
  const bare = version.replace(/^v/, '');
  return [`v${bare}`, bare, `release-${bare}`, `releases/${bare}`, `${bare}-release`];
}

export async function analyseProvenance(context: AnalysisContext): Promise<FamilyResult> {
  return runFamily('PROVENANCE', context, PROVENANCE_RULES, async (builder) => {
    const { metadata, files } = context.artifact;
    const repository = context.repository;

    const fired = new Set<string>();
    const mark = (ruleId: string): void => void fired.add(ruleId);

    // -----------------------------------------------------------------------
    // Q-PRV-001 — no repository field
    // -----------------------------------------------------------------------
    if (!metadata.repositoryUrl) {
      mark('Q-PRV-001');
      builder.fire('Q-PRV-001', 0.95, [
        metadataEvidence({ note: 'the package declares no repository' }),
      ]);

      // Nothing downstream can be compared without a source of truth.
      for (const ruleId of ['Q-PRV-002', 'Q-PRV-003', 'Q-PRV-004'] as const) {
        builder.skip(ruleId, 'NO_REPO');
      }
    } else {
      builder.pass('Q-PRV-001');

      // ---------------------------------------------------------------------
      // Q-PRV-002 — repository unreachable or archived
      // ---------------------------------------------------------------------
      if (!repository) {
        mark('Q-PRV-002');
        builder.fire('Q-PRV-002', 0.75, [
          metadataEvidence({
            repositoryUrl: metadata.repositoryUrl,
            note: 'the declared repository could not be read',
          }),
        ]);

        for (const ruleId of ['Q-PRV-003', 'Q-PRV-004'] as const) {
          builder.skip(ruleId, 'REPO_UNREACHABLE');
        }
      } else if (repository.archived) {
        mark('Q-PRV-002');
        builder.fire('Q-PRV-002', 0.6, [
          metadataEvidence({
            repositoryUrl: metadata.repositoryUrl,
            note: 'the repository is archived but the package is still publishing',
          }),
        ]);
      } else {
        builder.pass('Q-PRV-002');
      }
    }

    // -----------------------------------------------------------------------
    // Q-PRV-003 / Q-PRV-004 — the actual comparison
    // -----------------------------------------------------------------------
    if (repository && repository.files.size > 0) {
      const comparison = compareTrees(
        files.map((file) => ({ path: file.path, sha256: file.sha256 })),
        repository.files,
      );

      // ---------------------------------------------------------------------
      // Q-PRV-003 — files in the tarball that are not in the source tree
      // ---------------------------------------------------------------------
      // The event-stream signature. Weighted on whether the extra files can
      // actually run: an extra LICENSE is packaging, an extra .js file is the
      // whole attack.
      const extras = comparison.onlyInTarball;
      const executables = comparison.executableOnlyInTarball;

      if (executables.length > 0) {
        mark('Q-PRV-003');
        builder.fire(
          'Q-PRV-003',
          0.95,
          executables
            .slice(0, 20)
            .map((path) =>
              evidence(path, undefined, undefined, {
                note: 'present in the published tarball, absent from the source tree',
                sha256: files.find((file) => file.path === path)?.sha256 ?? null,
              }),
            ),
        );
      } else if (extras.length > PROVENANCE_EXTRA_FILE_TOLERANCE) {
        mark('Q-PRV-003');
        builder.fire('Q-PRV-003', 0.6, [
          metadataEvidence({
            extraFiles: extras.length,
            tolerance: PROVENANCE_EXTRA_FILE_TOLERANCE,
            examples: extras.slice(0, 5).join(', '),
          }),
        ]);
      } else {
        builder.pass('Q-PRV-003');
      }

      // ---------------------------------------------------------------------
      // Q-PRV-004 — files that exist in both but differ
      // ---------------------------------------------------------------------
      const compared = comparison.modified.length + comparison.identical.length;
      const ratio = compared > 0 ? comparison.modified.length / compared : 0;

      if (compared === 0) {
        builder.skip('Q-PRV-004', 'NO_TAG_MATCH');
      } else if (ratio > PROVENANCE_MODIFIED_RATIO) {
        mark('Q-PRV-004');
        builder.fire(
          'Q-PRV-004',
          ratio > 0.5 ? 0.85 : 0.65,
          comparison.modified
            .slice(0, 20)
            .map((path) =>
              evidence(path, undefined, undefined, {
                note: 'content differs between the tarball and the source tree',
              }),
            ),
        );
      } else {
        builder.pass('Q-PRV-004');
      }
    }

    // -----------------------------------------------------------------------
    // Q-PRV-005 — binary blobs in a source-only package
    // -----------------------------------------------------------------------
    const declaresNative =
      files.some((file) => /(?:^|\/)binding\.gyp$/.test(file.path)) ||
      Object.keys(metadata.dependencies).some((dependency) =>
        /node-gyp|prebuild|node-pre-gyp|node-addon-api|bindings/.test(dependency),
      ) ||
      metadata.keywords.some((keyword) => /native|binding|addon|ffi|wasm/i.test(keyword));

    const blobs = files.filter(
      (file) =>
        file.size >= BINARY_BLOB_MIN_BYTES &&
        (file.isBinary || BINARY_EXTENSIONS.test(file.path)) &&
        // Images, fonts and media are ordinary package content.
        !/\.(?:png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|otf|mp[34]|wav|pdf)$/i.test(file.path),
    );

    if (blobs.length > 0 && !declaresNative) {
      mark('Q-PRV-005');
      builder.fire(
        'Q-PRV-005',
        0.8,
        blobs
          .slice(0, 10)
          .map((file) =>
            evidence(file.path, undefined, undefined, {
              bytes: file.size,
              sha256: file.sha256,
            }),
          ),
      );
    } else {
      builder.pass('Q-PRV-005');
    }

    // -----------------------------------------------------------------------
    // Q-PRV-006 — no signed provenance attestation
    // -----------------------------------------------------------------------
    // Very low weight and very common: most packages have no attestation, and
    // its absence is a statement about ecosystem maturity rather than about
    // this package. It earns its place by making the presence of one count.
    if (metadata.hasProvenanceAttestation) {
      builder.pass('Q-PRV-006');
    } else {
      mark('Q-PRV-006');
      builder.fire('Q-PRV-006', 0.9, [
        metadataEvidence({
          note: 'no SLSA or Sigstore provenance attestation was published with this version',
        }),
      ]);
    }

    for (const ruleId of PROVENANCE_RULES) {
      if (!fired.has(ruleId)) builder.pass(ruleId);
    }
  });
}

/** Normalise a source file's bytes to a hash comparable with a tarball file. */
export function hashNormalised(content: Buffer): string {
  // Line endings are the one difference that survives everything else and means
  // nothing: a repository checked out on Windows differs from a tarball built on
  // Linux in every single line.
  const normalised = content.toString('utf8').replace(/\r\n/g, '\n');
  return createHash('sha256').update(normalised, 'utf8').digest('hex');
}

/** Build a snapshot from a fetched source tree. */
export function buildSnapshot(
  host: string,
  owner: string,
  repo: string,
  tag: string,
  files: Array<{ path: string; content: Buffer }>,
  archived: boolean,
): RepositorySnapshot {
  const map = new Map<string, string>();
  for (const file of files) map.set(file.path, hashNormalised(file.content));
  return { host, owner, repo, tag, files: map, archived };
}
