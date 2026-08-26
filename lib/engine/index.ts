import { randomUUID } from 'node:crypto';

import { AnalysisError } from '@/lib/errors';
import { logger } from '@/lib/logger';
import { extractTarball, withScanDirectory } from '@/lib/engine/extract';
import { fetchRepositorySnapshot } from '@/lib/engine/repository';
import * as npm from '@/lib/engine/registry/npm';
import * as pypi from '@/lib/engine/registry/pypi';
import { analyseCapability, deriveContextBucket } from '@/lib/engine/signals/capability';
import { analyseInstall } from '@/lib/engine/signals/install';
import { analyseMaintainer } from '@/lib/engine/signals/maintainer';
import { analyseObfuscation } from '@/lib/engine/signals/obfuscation';
import { analyseProvenance } from '@/lib/engine/signals/provenance';
import { analyseTyposquat } from '@/lib/engine/signals/typosquat';
import { modifierFor } from '@/lib/engine/signals/helpers';
import {
  ANALYSIS_BUDGET_MS,
  FAMILY_BUDGET_MS,
  PROVENANCE_BUDGET_MS,
} from '@/lib/engine/thresholds';
import type {
  AnalysisContext,
  AnalysisResult,
  Ecosystem,
  FamilyResult,
  PackageArtifact,
  PackageMetadata,
  RuleDefinition,
  Signal,
  SignalFamily,
} from '@/lib/engine/types';
import { decideVerdict } from '@/lib/engine/verdict';

/**
 * The orchestrator.
 *
 * ## Lifecycle, and the guarantee that matters
 *
 * Everything downstream of the download runs inside `withScanDirectory`, which
 * removes the per-scan temp directory in a `finally` block on every exit path —
 * success, thrown error, rejected promise, budget expiry. That is the SAFETY
 * RULE requirement, and it is enforced structurally rather than by remembering
 * to clean up: there is no way to obtain a scan directory without also
 * scheduling its destruction.
 *
 * ## Partial results
 *
 * The six families run through `Promise.allSettled` against a wall-clock
 * budget. One family failing — a registry timeout, an unparseable tree, a
 * repository that vanished — must never fail the analysis, because five
 * families of evidence is far more useful than none. A failed family is
 * recorded in `incompleteStages`, which lowers confidence, and its rules are
 * reported as skipped rather than passed.
 */

export interface AnalyseOptions {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  /** Rule catalogue. A disabled rule is evaluated as skipped. */
  rules: Map<string, RuleDefinition>;
  /** Tarball hashes already confirmed malicious, for the KNOWN_MALICIOUS path. */
  knownBadHashes?: ReadonlySet<string>;
  /** Overall wall-clock budget. */
  budgetMs?: number;
  /** Called as each stage completes, for streamed progress. */
  onProgress?: (event: ProgressEvent) => void;
  correlationId?: string;
}

export interface ProgressEvent {
  stage: string;
  status: 'started' | 'completed' | 'failed' | 'skipped';
  detail?: string;
  elapsedMs: number;
}

/**
 * Analyse one package version.
 *
 * Never executes, requires, imports or evaluates any package content, at any
 * point, on any path.
 */
export async function analyse(options: AnalyseOptions): Promise<AnalysisResult> {
  const {
    ecosystem,
    name,
    version,
    rules,
    knownBadHashes,
    budgetMs = ANALYSIS_BUDGET_MS,
    onProgress,
    correlationId = randomUUID(),
  } = options;

  const startedAt = Date.now();
  const deadline = startedAt + budgetMs;
  const incompleteStages: string[] = [];

  const progress = (stage: string, status: ProgressEvent['status'], detail?: string): void => {
    onProgress?.({
      stage,
      status,
      ...(detail === undefined ? {} : { detail }),
      elapsedMs: Date.now() - startedAt,
    });
  };

  const log = logger.child({ correlationId, ecosystem, name, version });

  // -------------------------------------------------------------------------
  // 1. Metadata
  // -------------------------------------------------------------------------
  progress('metadata', 'started');
  let metadata: PackageMetadata;
  try {
    metadata =
      ecosystem === 'NPM'
        ? await npm.fetchPackageMetadata(name, version)
        : await pypi.fetchPackageMetadata(name, version);
    progress('metadata', 'completed');
  } catch (error) {
    progress('metadata', 'failed', 'registry metadata could not be read');
    // Without metadata there is no package to analyse. This is the one
    // unrecoverable failure in the pipeline.
    throw error instanceof AnalysisError
      ? error
      : new AnalysisError('NO_METADATA', 'The registry could not be reached.', { cause: error });
  }

  if (!metadata.tarballUrl) {
    throw new AnalysisError('NO_TARBALL', 'The registry lists no downloadable archive.');
  }

  // -------------------------------------------------------------------------
  // 2. Download
  // -------------------------------------------------------------------------
  progress('download', 'started');
  const downloaded =
    ecosystem === 'NPM'
      ? await npm.downloadTarball(metadata.tarballUrl, metadata.integrity)
      : await pypi.downloadSdist(metadata.tarballUrl, metadata.integrity);
  progress('download', 'completed', `${downloaded.bytes.length} bytes`);

  // -------------------------------------------------------------------------
  // 3. Everything else, inside a scan directory that is always removed
  // -------------------------------------------------------------------------
  return withScanDirectory(async (root) => {
    progress('extract', 'started');
    const extraction = await extractTarball(downloaded.bytes, root);
    progress(
      'extract',
      'completed',
      `${extraction.files.length} files, ${extraction.rejected.length} rejected`,
    );

    const artifact: PackageArtifact = {
      metadata,
      files: extraction.files,
      tarballSha256: downloaded.sha256,
      totalBytes: extraction.totalBytes,
      extractionRoot: root,
    };

    const contextBucket = deriveContextBucket(metadata);

    // -----------------------------------------------------------------------
    // 4. Repository snapshot, for provenance
    // -----------------------------------------------------------------------
    progress('repository', 'started');
    let repository: AnalysisContext['repository'];
    if (metadata.repositoryUrl) {
      try {
        const snapshot = await fetchRepositorySnapshot(
          metadata.repositoryUrl,
          metadata.version,
          Math.min(PROVENANCE_BUDGET_MS, Math.max(0, deadline - Date.now())),
        );
        if (snapshot) {
          repository = snapshot;
          progress('repository', 'completed', `${snapshot.files.size} files at ${snapshot.tag}`);
        } else {
          progress('repository', 'skipped', 'no matching tag');
          incompleteStages.push('repository');
        }
      } catch (error) {
        log.debug({ err: error }, 'repository snapshot unavailable');
        progress('repository', 'failed', 'repository could not be read');
        incompleteStages.push('repository');
      }
    } else {
      progress('repository', 'skipped', 'the package declares no repository');
    }

    const context: AnalysisContext = {
      artifact,
      rules,
      contextBucket,
      deadline,
      correlationId,
      ...(repository ? { repository } : {}),
    };

    // -----------------------------------------------------------------------
    // 5. The six families, in parallel, each individually bounded
    // -----------------------------------------------------------------------
    const families: Array<{ family: SignalFamily; run: () => Promise<FamilyResult> }> = [
      { family: 'INSTALL', run: () => analyseInstall(context) },
      { family: 'OBFUSCATION', run: () => analyseObfuscation(context) },
      { family: 'CAPABILITY', run: () => analyseCapability(context) },
      { family: 'TYPOSQUAT', run: () => analyseTyposquat(context) },
      { family: 'MAINTAINER', run: () => analyseMaintainer(context) },
      { family: 'PROVENANCE', run: () => analyseProvenance(context) },
    ];

    progress('signals', 'started');

    const settled = await Promise.allSettled(
      families.map(async ({ family, run }) => {
        const familyBudget = Math.min(
          FAMILY_BUDGET_MS,
          Math.max(0, deadline - Date.now()),
        );
        return withTimeout(run(), familyBudget, family);
      }),
    );

    const results: FamilyResult[] = [];

    for (let index = 0; index < settled.length; index++) {
      const outcome = settled[index];
      const descriptor = families[index];
      if (!outcome || !descriptor) continue;

      if (outcome.status === 'fulfilled') {
        results.push(outcome.value);
        if (outcome.value.error) {
          incompleteStages.push(descriptor.family);
          progress(descriptor.family, 'failed', outcome.value.error);
        } else {
          progress(descriptor.family, 'completed', `${outcome.value.durationMs}ms`);
        }
      } else {
        // A family that rejected outright still contributes its rules as
        // skipped, so the report shows what was not checked.
        log.warn(
          { err: outcome.reason, family: descriptor.family },
          'signal family rejected; continuing with partial results',
        );
        incompleteStages.push(descriptor.family);
        progress(descriptor.family, 'failed', 'family did not complete');
        results.push({
          family: descriptor.family,
          signals: [],
          error: outcome.reason instanceof Error ? outcome.reason.message : 'Family failed.',
          durationMs: 0,
        });
      }
    }

    progress('signals', 'completed');

    // -----------------------------------------------------------------------
    // 6. Verdict
    // -----------------------------------------------------------------------
    const signals: Signal[] = results.flatMap((result) => result.signals);

    const outcome = decideVerdict({
      signals,
      rules,
      incompleteStages,
      knownBadHashMatch: knownBadHashes?.has(downloaded.sha256) ?? false,
    });

    progress('verdict', 'completed', outcome.verdict);

    return {
      ecosystem,
      name: metadata.name,
      version: metadata.version,
      verdict: outcome.verdict,
      confidence: outcome.confidence,
      weightedScore: outcome.weightedScore,
      signals,
      hardTriggers: outcome.hardTriggers,
      contextBucket,
      contextModifier: modifierFor('CAPABILITY', contextBucket),
      families: results,
      incompleteStages,
      tarballSha256: downloaded.sha256,
      catalogue: {
        description: metadata.description,
        license: metadata.license,
        repositoryUrl: metadata.repositoryUrl,
        weeklyDownloads: metadata.weeklyDownloads,
        maintainerCount: metadata.maintainers.length,
        publishedAt: metadata.publishedAt,
        firstPublishedAt: earliestRelease(metadata),
        tarballUrl: metadata.tarballUrl,
        integrity: metadata.integrity,
        unpackedSize: extraction.totalBytes,
        hasProvenanceAttestation: metadata.hasProvenanceAttestation,
      },
      durationMs: Date.now() - startedAt,
      partial: incompleteStages.length > 0,
    };
  });
}

/** Earliest publish time in the release history, or the analysed version's own. */
function earliestRelease(metadata: PackageMetadata): Date | null {
  let earliest: Date | null = metadata.publishedAt;
  for (const release of metadata.releaseHistory) {
    if (!earliest || release.publishedAt < earliest) earliest = release.publishedAt;
  }
  return earliest;
}

/**
 * Bound a family's runtime.
 *
 * A timeout resolves to a failed FamilyResult rather than rejecting, so one
 * slow family degrades the analysis instead of ending it. The underlying
 * promise is abandoned, not cancelled — there is no cancellation primitive for
 * an arbitrary async function — but everything it can touch lives inside the
 * scan directory, which is removed regardless.
 */
async function withTimeout(
  work: Promise<FamilyResult>,
  budgetMs: number,
  family: SignalFamily,
): Promise<FamilyResult> {
  if (budgetMs <= 0) {
    return { family, signals: [], error: 'Budget exhausted before this family ran.', durationMs: 0 };
  }

  let timer: NodeJS.Timeout | undefined;

  const timeout = new Promise<FamilyResult>((resolve) => {
    timer = setTimeout(
      () =>
        resolve({
          family,
          signals: [],
          error: `Family exceeded its ${budgetMs}ms budget.`,
          durationMs: budgetMs,
        }),
      budgetMs,
    );
  });

  try {
    return await Promise.race([work, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export { deriveContextBucket };
export type { AnalysisResult };
