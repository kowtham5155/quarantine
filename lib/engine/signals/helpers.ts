import { readFile } from 'node:fs/promises';

import { parseSource, type ParsedFile } from '@/lib/engine/ast';
import { MAX_EXCERPT_BYTES } from '@/lib/engine/extract';
import {
  CONFIDENCE_MAX,
  CONFIDENCE_MIN,
  CONFIDENCE_UNPARSED,
  CONTEXT_MODIFIED_FAMILIES,
  CONTEXT_MODIFIERS,
  CONTEXT_MODIFIER_FLOOR,
  MAX_PARSED_FILES,
  type ContextBucket,
} from '@/lib/engine/thresholds';
import type {
  AnalysisContext,
  Evidence,
  ExtractedFile,
  FamilyResult,
  Signal,
  SignalFamily,
  SkipReason,
} from '@/lib/engine/types';
import { logger } from '@/lib/logger';

/**
 * Shared plumbing for the six signal modules.
 *
 * Two things live here rather than being repeated six times: building a Signal
 * with the right confidence and context modifier applied, and reading package
 * files safely. Neither ever executes package content.
 */

// ---------------------------------------------------------------------------
// Signal construction
// ---------------------------------------------------------------------------

export function clampConfidence(value: number): number {
  if (!Number.isFinite(value)) return CONFIDENCE_MIN;
  return Math.min(CONFIDENCE_MAX, Math.max(CONFIDENCE_MIN, value));
}

/** The context multiplier for a family, floored so context never erases a signal. */
export function modifierFor(family: SignalFamily, bucket: ContextBucket): number {
  const applies = (CONTEXT_MODIFIED_FAMILIES as readonly string[]).includes(family);
  if (!applies) return 1;
  return Math.max(CONTEXT_MODIFIER_FLOOR, CONTEXT_MODIFIERS[bucket]);
}

export interface SignalBuilder {
  /** Record a fired rule. Repeated calls for the same rule merge evidence. */
  fire(ruleId: string, confidence: number, evidence: Evidence[]): void;
  /** Record a rule that was evaluated and did not match. */
  pass(ruleId: string): void;
  /** Record a rule that could not be evaluated at all. */
  skip(ruleId: string, reason: SkipReason): void;
  /** Every signal, in catalogue order. */
  collect(): Signal[];
}

/**
 * Accumulates signals for one family.
 *
 * A rule that is never mentioned by its module still appears in the output as
 * not-fired, because "we checked and found nothing" and "we never checked" are
 * different claims and a report has to be able to tell them apart.
 */
export function createSignalBuilder(
  family: SignalFamily,
  context: AnalysisContext,
  ruleIds: readonly string[],
): SignalBuilder {
  const modifier = modifierFor(family, context.contextBucket);
  const signals = new Map<string, Signal>();

  for (const ruleId of ruleIds) {
    signals.set(ruleId, {
      ruleId,
      family,
      fired: false,
      confidence: 0,
      contextModifier: modifier,
      evidence: [],
    });
  }

  const enabled = (ruleId: string): boolean => context.rules.get(ruleId)?.enabled !== false;

  return {
    fire(ruleId, confidence, evidence) {
      const signal = signals.get(ruleId);
      if (!signal) return;
      if (!enabled(ruleId)) {
        signal.skipped = 'NOT_APPLICABLE';
        return;
      }

      signal.fired = true;
      // Repeated hits raise confidence toward the ceiling but never past it.
      signal.confidence = clampConfidence(Math.max(signal.confidence, confidence));
      // Evidence is capped: a rule that matches 40,000 times is not 40,000
      // times more informative, and the report has to stay renderable.
      signal.evidence = [...signal.evidence, ...evidence].slice(0, 25);
    },

    pass(ruleId) {
      const signal = signals.get(ruleId);
      if (signal && !signal.fired) signal.fired = false;
    },

    skip(ruleId, reason) {
      const signal = signals.get(ruleId);
      if (signal && !signal.fired) signal.skipped = reason;
    },

    collect() {
      return [...signals.values()];
    },
  };
}

/** Wrap a family body so a thrown error becomes a partial result, never a crash. */
export async function runFamily(
  family: SignalFamily,
  context: AnalysisContext,
  ruleIds: readonly string[],
  body: (builder: SignalBuilder) => Promise<void>,
): Promise<FamilyResult> {
  const startedAt = Date.now();
  const builder = createSignalBuilder(family, context, ruleIds);

  try {
    await body(builder);
    return { family, signals: builder.collect(), durationMs: Date.now() - startedAt };
  } catch (error) {
    logger.error(
      { err: error, family, correlationId: context.correlationId },
      'signal family failed',
    );
    // Whatever was collected before the failure is still reported; the rest is
    // marked skipped so the incompleteness penalty can see it.
    for (const ruleId of ruleIds) builder.skip(ruleId, 'BUDGET_EXHAUSTED');
    return {
      family,
      signals: builder.collect(),
      error: error instanceof Error ? error.message : 'Family failed.',
      durationMs: Date.now() - startedAt,
    };
  }
}

// ---------------------------------------------------------------------------
// File access
// ---------------------------------------------------------------------------

/**
 * Read a file from the scan directory as text.
 *
 * Reads bytes. Never requires, imports or evaluates. Returns null rather than
 * throwing, because a file that cannot be read is a fact about the package.
 */
export async function readText(file: ExtractedFile): Promise<string | null> {
  if (file.isBinary) return null;
  try {
    const bytes = await readFile(file.absolutePath);
    return bytes.toString('utf8');
  } catch (error) {
    logger.debug({ err: error, path: file.path }, 'could not read package file');
    return null;
  }
}

const SOURCE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.mts', '.cts', '.tsx']);

export function isJavaScriptFile(file: ExtractedFile): boolean {
  const dot = file.path.lastIndexOf('.');
  if (dot < 0) return false;
  return SOURCE_EXTENSIONS.has(file.path.slice(dot).toLowerCase());
}

export interface LoadedSource {
  file: ExtractedFile;
  text: string;
  parsed: ParsedFile;
}

/**
 * Load and parse the package's JavaScript, bounded by `MAX_PARSED_FILES`.
 *
 * When the package has more source files than the budget allows, the largest
 * are kept: a dropper is more often a big blob of encoded payload than a small
 * helper, and a truncated analysis should keep the files most likely to matter.
 * The caller is told how many were skipped so confidence can reflect it.
 */
export async function loadSources(
  files: ExtractedFile[],
  limit = MAX_PARSED_FILES,
): Promise<{ sources: LoadedSource[]; skipped: number }> {
  const candidates = files.filter(isJavaScriptFile).sort((a, b) => b.size - a.size);
  const selected = candidates.slice(0, limit);

  const sources: LoadedSource[] = [];
  for (const file of selected) {
    const text = await readText(file);
    if (text === null) continue;
    sources.push({ file, text, parsed: parseSource(file.path, text) });
  }

  return { sources, skipped: Math.max(0, candidates.length - selected.length) };
}

/** Confidence for a hit in a file the parser could not handle. */
export function confidenceForSource(source: LoadedSource, whenParsed: number): number {
  return source.parsed.parsed ? whenParsed : CONFIDENCE_UNPARSED;
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/**
 * Build an Evidence record.
 *
 * `excerpt` is verbatim package content and is hostile by construction. It is
 * truncated here and must still be escaped wherever it is rendered.
 */
export function evidence(
  file: string,
  line: number | undefined,
  excerpt: string | undefined,
  detail?: Record<string, string | number | boolean | null>,
): Evidence {
  const record: Evidence = { file };
  if (line !== undefined) {
    record.startLine = line;
    record.endLine = line;
  }
  if (excerpt !== undefined) {
    record.excerpt = excerpt.slice(0, 200);
  }
  if (detail) record.detail = detail;
  return record;
}

/**
 * Evidence for a finding that has no file — an identity or metadata signal.
 * The detail map carries the whole finding.
 */
export function metadataEvidence(
  detail: Record<string, string | number | boolean | null>,
): Evidence {
  return { detail };
}

/** A one-line excerpt around a character offset in a raw string. */
export function excerptAround(text: string, index: number, radius = 80): string {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + radius);
  return text.slice(start, end).replace(/\s+/g, ' ').trim();
}

/** Line number for a character offset in a raw string. */
export function lineOf(text: string, index: number): number {
  let line = 1;
  const limit = Math.min(index, text.length);
  for (let position = 0; position < limit; position++) {
    if (text[position] === '\n') line++;
  }
  return line;
}

export { MAX_EXCERPT_BYTES };
