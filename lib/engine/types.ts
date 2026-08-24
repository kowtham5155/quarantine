import type { Ecosystem, Severity, SignalFamily } from '@prisma/client';

import type { Verdict } from '@/lib/constants';
import type { ContextBucket } from '@/lib/engine/thresholds';

/**
 * The engine's vocabulary.
 *
 * Everything here is a plain data type. The engine never hands a live handle —
 * a file descriptor, a stream, a parsed AST — across a module boundary, because
 * the things it is describing came out of a hostile archive and the fewer
 * places they can be acted on, the better.
 *
 * Every string on these types that originated in a package (`name`, `excerpt`,
 * `file`, maintainer names, repository URLs) is untrusted. Render it through
 * `lib/safe-display.ts`; never interpolate it into HTML, a shell command, a
 * file path, or a query.
 */

export type { Verdict };
export type { Ecosystem, Severity, SignalFamily };

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/**
 * Where a signal fired. Every field is optional because signals differ in what
 * they can point at: a typosquat hit has no file, and a metadata signal has no
 * line. A signal with no evidence at all is still valid but reads as weaker.
 */
export interface Evidence {
  /** Package-relative POSIX path. Never an absolute path from the temp dir. */
  file?: string;
  /** 1-indexed, inclusive. */
  startLine?: number;
  endLine?: number;
  /**
   * A short, already-truncated fragment of the matching source.
   *
   * HOSTILE INPUT. This is attacker-controlled by construction — it is a
   * verbatim slice of the package being analysed. It is length-capped at
   * extraction time and must still be escaped on render.
   */
  excerpt?: string;
  /** Free-form structured detail, e.g. `{ distance: 1, target: 'lodash' }`. */
  detail?: Record<string, string | number | boolean | null>;
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

/**
 * One rule's outcome for one package.
 *
 * The engine emits a Signal for every rule it evaluated, fired or not. A report
 * that only lists hits cannot answer "did you check for that?", and the answer
 * to that question is most of what makes a verdict trustworthy.
 */
export interface Signal {
  /** Catalogue identifier, e.g. `Q-INS-002`. */
  ruleId: string;
  family: SignalFamily;
  fired: boolean;
  /**
   * How much the engine trusts this particular hit, 0–1. Distinct from the
   * rule's weight: weight is how much the rule matters, confidence is how sure
   * we are that it really matched.
   */
  confidence: number;
  /**
   * Context multiplier applied to this signal, 1.0 when the family is not
   * context-modified. Recorded per signal so a report can show the arithmetic.
   */
  contextModifier: number;
  /** Every place the rule matched. Empty when `fired` is false. */
  evidence: Evidence[];
  /**
   * Set when the rule could not be evaluated at all — no repository to compare
   * against, file unreadable, budget exhausted. A skipped rule is not a passed
   * rule, and the distinction feeds the incompleteness penalty.
   */
  skipped?: SkipReason;
}

export type SkipReason =
  | 'NO_REPO'
  | 'REPO_UNREACHABLE'
  | 'NO_TAG_MATCH'
  | 'NO_METADATA'
  | 'NO_DOWNLOAD_DATA'
  | 'UNPARSEABLE'
  | 'BUDGET_EXHAUSTED'
  | 'NOT_APPLICABLE';

/** A rule as the engine needs it: catalogue metadata plus its weight. */
export interface RuleDefinition {
  ruleId: string;
  family: SignalFamily;
  name: string;
  description: string;
  severity: Severity;
  baseWeight: number;
  enabled: boolean;
}

// ---------------------------------------------------------------------------
// The artefact under analysis
// ---------------------------------------------------------------------------

/** One file recovered from the tarball. Content is never executed, only read. */
export interface ExtractedFile {
  /** Package-relative POSIX path, with the leading `package/` prefix stripped. */
  path: string;
  /** Size in bytes as written to disk. */
  size: number;
  /** Absolute path inside the per-scan temp dir. Valid only during the scan. */
  absolutePath: string;
  /** Sniffed from a prefix of the file, not from the extension. */
  isBinary: boolean;
  /** SHA-256 of the file's bytes, for provenance comparison and campaign clustering. */
  sha256: string;
}

/**
 * Registry metadata for the specific version under analysis.
 *
 * Everything here is attacker-controlled except the timestamps and download
 * counts, which come from the registry rather than from the package author.
 */
export interface PackageMetadata {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  description: string | null;
  keywords: string[];
  license: string | null;
  repositoryUrl: string | null;
  homepage: string | null;
  /** Declared `scripts` block, verbatim. Never executed. */
  scripts: Record<string, string>;
  dependencies: Record<string, string>;
  /** Names only; the registry's email fields are not retained. */
  maintainers: Maintainer[];
  /** Publish time of this version. */
  publishedAt: Date | null;
  /** Publish times of every version, for cadence and dormancy analysis. */
  releaseHistory: ReleaseRecord[];
  /** Downloads in the trailing week, when the registry exposes them. */
  weeklyDownloads: number | null;
  /** Reverse-dependency count, when available. */
  dependentCount: number | null;
  tarballUrl: string | null;
  /** Registry-published integrity string for the tarball, if any. */
  integrity: string | null;
  /** True when the registry reports a signed provenance attestation. */
  hasProvenanceAttestation: boolean;
}

export interface Maintainer {
  name: string;
  /** Account creation time. npm does not expose this publicly; usually null. */
  accountCreatedAt: Date | null;
  /** Number of packages this account maintains, when known. */
  packageCount: number | null;
  /** When this maintainer first appears in the package's own history. */
  firstSeenAt: Date | null;
}

export interface ReleaseRecord {
  version: string;
  publishedAt: Date;
}

/**
 * Everything one analysis pass operates on.
 *
 * Assembled once by the orchestrator and passed to every signal module. Signal
 * modules are pure with respect to it: they read, they never mutate.
 */
export interface PackageArtifact {
  metadata: PackageMetadata;
  files: ExtractedFile[];
  /** SHA-256 of the tarball as downloaded. */
  tarballSha256: string;
  /** Total extracted size, for reporting. */
  totalBytes: number;
  /** Root of the per-scan temp dir. Deleted before the analysis returns. */
  extractionRoot: string;
}

// ---------------------------------------------------------------------------
// Analysis context
// ---------------------------------------------------------------------------

/**
 * The environment a signal module runs in: the artefact, the rule catalogue,
 * the derived context bucket, and a deadline it is expected to respect.
 */
export interface AnalysisContext {
  artifact: PackageArtifact;
  /** Rule catalogue keyed by ruleId, so a disabled rule can be skipped. */
  rules: Map<string, RuleDefinition>;
  /** Declared-purpose bucket, derived from metadata only. */
  contextBucket: ContextBucket;
  /** Wall-clock time after which a module should stop and return what it has. */
  deadline: number;
  /** Correlation id, threaded into every log line for this analysis. */
  correlationId: string;
  /** Source trees for provenance, when one could be fetched. */
  repository?: RepositorySnapshot;
}

/** A normalised source tree fetched from a git host, for provenance comparison. */
export interface RepositorySnapshot {
  /** Resolved host, e.g. `github.com`. */
  host: string;
  owner: string;
  repo: string;
  /** The tag that matched this version, e.g. `v1.2.3`. */
  tag: string;
  /** Path -> SHA-256, already normalised. */
  files: Map<string, string>;
  archived: boolean;
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/** What one signal module returns. */
export interface FamilyResult {
  family: SignalFamily;
  signals: Signal[];
  /** Set when the family could not complete; its signals are then partial. */
  error?: string;
  durationMs: number;
}

export interface HardTriggerHit {
  id: string;
  label: string;
  /** Rule ids whose combination fired this trigger. */
  ruleIds: string[];
}

/** The engine's complete output for one package version. */
export interface AnalysisResult {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  verdict: Verdict;
  /** Overall confidence in the verdict, 0–1. */
  confidence: number;
  weightedScore: number;
  /** Every rule evaluated, fired and not fired. */
  signals: Signal[];
  hardTriggers: HardTriggerHit[];
  contextBucket: ContextBucket;
  contextModifier: number;
  /** Per-family timing and failure detail. */
  families: FamilyResult[];
  /** Families that failed or were skipped, feeding the incompleteness penalty. */
  incompleteStages: string[];
  tarballSha256: string | null;
  durationMs: number;
  /** True when at least one family failed and the result is partial. */
  partial: boolean;
}

/** A signal module: pure, bounded, and never touching the filesystem outside the scan root. */
export type SignalModule = (context: AnalysisContext) => Promise<FamilyResult>;
