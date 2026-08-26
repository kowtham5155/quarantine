/**
 * Every tunable detection threshold in the engine.
 *
 * ## Why this file exists
 *
 * A detection engine is a pile of numbers wearing a trench coat. Scattered
 * inline they are invisible: nobody can tell which constant moved a verdict,
 * nobody can diff two configurations, and nobody can tune them without grepping
 * the whole codebase. Collected here they become a single artefact that can be
 * reviewed, versioned and — in phase 8 — fitted against the labelled corpus.
 *
 * ## Provisional status
 *
 * **Every value in this file is a provisional guess.** They are seeded from
 * published incident write-ups, from the shape of the corpus, and from
 * judgement about which errors are cheaper to make. None of them has been
 * fitted against measured precision and recall yet. Phase 8 runs the corpus
 * evaluation and replaces these numbers with tuned ones; until then, treat any
 * verdict near a bucket boundary as an opinion rather than a measurement.
 *
 * Each constant below records what it controls and which direction the error
 * goes when it is wrong, because that is what a tuner needs to know.
 *
 * ## Rules
 *
 * - No detection threshold lives anywhere else. Signal modules import from here.
 * - Nothing in this file may import from the rest of the engine: it is a leaf,
 *   so that a tuning harness can load it without loading an analyser.
 */

// ---------------------------------------------------------------------------
// Entropy — Q-OBF-001
// ---------------------------------------------------------------------------

/**
 * Shannon entropy, in bits per character, above which a string literal is
 * treated as probably-encoded rather than probably-prose.
 *
 * English prose sits near 4.0–4.5 bits/char over a printable alphabet.
 * Base64-encoded data sits near 5.5–6.0. Minified but unencoded JavaScript
 * lands awkwardly in between, which is why this pairs with a length floor
 * rather than firing on its own.
 *
 * PROVISIONAL. Too low and every minified bundle and source map is suspicious;
 * too high and a padded payload slips under. Tune in phase 8.
 */
export const ENTROPY_BITS_PER_CHAR = 4.8;

/**
 * Minimum length before entropy is even measured. Short strings have unstable
 * entropy — `"a1b2c3"` scores like ciphertext — so measuring them produces
 * noise, not signal.
 *
 * PROVISIONAL. Too low produces false positives on hashes and UUIDs embedded in
 * ordinary code; too high misses compact droppers.
 */
export const ENTROPY_MIN_LENGTH = 64;

/**
 * Entropy at or above this is treated as certainly-encoded, and raises the
 * signal's confidence rather than just firing it.
 *
 * PROVISIONAL. Compressed or encrypted bytes approach 8.0; 5.9 is chosen to sit
 * above clean base64 without demanding raw ciphertext.
 */
export const ENTROPY_HIGH_CONFIDENCE = 5.9;

// ---------------------------------------------------------------------------
// Encoded payload sizes — Q-OBF-002, Q-OBF-004
// ---------------------------------------------------------------------------

/**
 * A base64 or hex literal at least this long is reported. The spec calls for
 * 1KB; small enough to catch a staged loader, large enough that inline images,
 * fonts and test vectors do not dominate the results.
 *
 * PROVISIONAL. Lowering this sharply increases hits on legitimate embedded
 * assets, which is the main false-positive source in this family.
 */
export const ENCODED_LITERAL_MIN_BYTES = 1024;

/** An encoded literal this large is almost never an asset. Raises confidence. */
export const ENCODED_LITERAL_HIGH_CONFIDENCE_BYTES = 16 * 1024;

/**
 * Number of members a string array must have before it is considered the
 * lookup table half of the classic JS-obfuscator string-array pattern.
 *
 * PROVISIONAL. Real obfuscator output typically emits hundreds; legitimate
 * constant tables (locale lists, unit names) can reach the low tens.
 */
export const STRING_ARRAY_MIN_MEMBERS = 40;

/**
 * Fraction of a candidate string array's members that must look encoded
 * (hex escapes, base64, non-word characters) for the array to count.
 *
 * PROVISIONAL. Below this a legitimate constant table matches too easily.
 */
export const STRING_ARRAY_ENCODED_RATIO = 0.6;

/**
 * Depth of nested string concatenation that counts as dynamic identifier
 * construction rather than ordinary formatting — Q-OBF-007.
 *
 * PROVISIONAL. Hand-written template building rarely nests past four or five;
 * obfuscators routinely produce dozens.
 */
export const CONCAT_DEPTH = 8;

// ---------------------------------------------------------------------------
// Minification — Q-OBF-006
// ---------------------------------------------------------------------------

/**
 * Average source line length, in characters, above which a file is treated as
 * minified. Hand-written JavaScript very rarely averages past 120 even with
 * long imports and generous formatting.
 *
 * PROVISIONAL. Files under `MINIFIED_MIN_FILE_BYTES` are exempt, because a
 * short file's average is dominated by a single long line.
 */
export const MINIFIED_AVG_LINE_LENGTH = 500;

/** Below this size, line-length averages are too noisy to judge minification. */
export const MINIFIED_MIN_FILE_BYTES = 4 * 1024;

// ---------------------------------------------------------------------------
// Typosquatting — Q-TYP-*
// ---------------------------------------------------------------------------

/**
 * Maximum Damerau-Levenshtein distance from a known-popular package name for
 * the candidate to be considered a typosquat. Distance 1 is the overwhelming
 * majority of real cases; 2 catches double substitutions at a real cost in
 * false positives.
 *
 * PROVISIONAL. Raising this to 3 makes short names collide with each other
 * indiscriminately, which is why `TYPOSQUAT_MIN_NAME_LENGTH` exists.
 */
export const TYPOSQUAT_MAX_DISTANCE = 2;

/**
 * Names shorter than this are not checked for edit distance at all. Among
 * three- and four-character names, distance 2 relates almost every name to
 * every other one, and the result is noise.
 *
 * PROVISIONAL.
 */
export const TYPOSQUAT_MIN_NAME_LENGTH = 5;

/**
 * Weekly download count at or above which a package is presumed to be a real,
 * established package rather than a squat of one — even if its name is one edit
 * from something more popular.
 *
 * This is the single most important false-positive suppressor in the family.
 * Without it, every legitimate sibling package (`react-dom` beside `react-dnd`,
 * `lodash.get` beside `lodash.set`) is accused of squatting its neighbour.
 *
 * PROVISIONAL, and the value most likely to move in phase 8. Too low and squats
 * that have already achieved some install volume are excused; too high and
 * mid-popularity legitimate packages are accused.
 */
export const TYPOSQUAT_DOWNLOAD_SUPPRESSION_FLOOR = 25_000;

/**
 * Ratio between the candidate's downloads and the target's, above which the two
 * are treated as peers rather than as squat and victim. A package with a tenth
 * of the traffic of the name it resembles is a plausible squat; one with half
 * of it is more likely a sibling or a fork.
 *
 * PROVISIONAL.
 */
export const TYPOSQUAT_PEER_DOWNLOAD_RATIO = 0.1;

/**
 * Affixes that, appended to or prepended around a popular name, characterise
 * combosquatting — Q-TYP-005. Kept here rather than in the signal module
 * because which affixes count is exactly the kind of thing corpus evaluation
 * revises.
 *
 * PROVISIONAL.
 */
export const COMBOSQUAT_AFFIXES = [
  'js',
  'lib',
  'core',
  'cli',
  'sdk',
  'api',
  'node',
  'official',
  'dev',
  'pro',
  'plus',
  'ng',
  'v2',
  'new',
  'real',
] as const;

// ---------------------------------------------------------------------------
// Maintainer and release forensics — Q-MNT-*
// ---------------------------------------------------------------------------

/**
 * Silence, in days, that must precede a release for it to count as a dormancy
 * break — Q-MNT-001. This is the event-stream shape: a package sits untouched
 * for the better part of a year, then ships.
 *
 * PROVISIONAL. Many entirely healthy packages are simply finished and release
 * once a year, so this fires on benign packages constantly and must carry low
 * standalone weight; its value is as corroboration.
 */
export const DORMANCY_DAYS = 180;

/** Dormancy beyond this is treated as a stronger signal. PROVISIONAL. */
export const DORMANCY_SEVERE_DAYS = 540;

/**
 * Window, in days, within which a maintainer added *before* a release makes
 * that release suspicious — Q-MNT-002. The event-stream compromise had the
 * handover and the malicious publish within weeks of each other.
 *
 * PROVISIONAL.
 */
export const MAINTAINER_ADDED_WINDOW_DAYS = 30;

/**
 * Age, in days, below which a maintainer account is considered new — Q-MNT-003.
 * Attackers register throwaway accounts shortly before a takeover.
 *
 * PROVISIONAL. npm does not publish account creation dates through the public
 * registry API, so this is applied only where the data is actually available
 * and the signal degrades to not-fired otherwise, rather than guessing.
 */
export const MAINTAINER_NEW_ACCOUNT_DAYS = 90;

/** Package count below which a maintainer account reads as thin. PROVISIONAL. */
export const MAINTAINER_FEW_PACKAGES = 3;

/**
 * Weekly downloads above which a package counts as high-traffic for the
 * purposes of Q-MNT-004 (sole maintainer on a package many people depend on).
 * This is a bus-factor observation, not an accusation, and carries low weight.
 *
 * PROVISIONAL.
 */
export const SOLE_MAINTAINER_DOWNLOAD_FLOOR = 100_000;

/**
 * Major-version jump that counts as anomalous — Q-MNT-005. Version 1.2.3
 * followed by 9.0.0 is a common trick to get a malicious release picked up by
 * loose ranges and to sit at the top of a version list.
 *
 * PROVISIONAL.
 */
export const VERSION_JUMP_MAJOR = 2;

/**
 * Multiple of a package's own median release interval that counts as a cadence
 * anomaly — Q-MNT-006. Measured against the package's own history rather than
 * an absolute, because release rhythms differ wildly between projects.
 *
 * PROVISIONAL.
 */
export const CADENCE_ANOMALY_MULTIPLE = 8;

/** Releases needed before a median cadence is meaningful at all. PROVISIONAL. */
export const CADENCE_MIN_RELEASES = 5;

// ---------------------------------------------------------------------------
// Provenance — Q-PRV-*
// ---------------------------------------------------------------------------

/**
 * Number of files present in the tarball but absent from the source tree that
 * is treated as noise rather than divergence — Q-PRV-003.
 *
 * Build output, generated types and packaging shims routinely appear in a
 * tarball and not in git. The normaliser strips the ones it recognises; this
 * absorbs the residue. Zero would make the highest-value signal in the engine
 * fire on almost every package, which would destroy its credibility.
 *
 * PROVISIONAL, and worth careful attention in phase 8: this constant trades the
 * event-stream detection directly against a flood of false positives.
 */
export const PROVENANCE_EXTRA_FILE_TOLERANCE = 2;

/**
 * When most of the runnable files in a tarball are absent from the source tree,
 * the package is published from a build rather than tampered with.
 *
 * lodash@4.17.21 is the case that forced this: its tag tree holds 148 files and
 * its published tarball holds over a thousand, because the per-method modules
 * are generated at release. Treating that as the event-stream signature scores
 * one of the most-downloaded packages on npm as LIKELY_MALICIOUS. The injected
 * file that Q-PRV-003 exists to catch looks nothing like it — event-stream's
 * tarball corresponded to its repository except for a handful of extra files.
 */
export const PROVENANCE_BUILD_OUTPUT_SHARE = 0.5;

/** At or below this many extra runnable files, scale cannot excuse them. */
export const PROVENANCE_INJECTED_FILE_MAX = 5;

/**
 * Fraction of compared files that may differ in content before the trees are
 * called divergent — Q-PRV-004. Line-ending and banner-comment differences
 * survive normalisation more often than one would like.
 *
 * PROVISIONAL.
 */
export const PROVENANCE_MODIFIED_RATIO = 0.15;

/**
 * A file this large that is binary, inside a package declaring itself pure
 * JavaScript, is reported — Q-PRV-005.
 *
 * PROVISIONAL. Small binaries are usually icons or test fixtures.
 */
export const BINARY_BLOB_MIN_BYTES = 16 * 1024;

/**
 * Fraction of bytes in a sample that must be non-printable for a file to be
 * classified as binary. Applied to a prefix of the file, not all of it.
 *
 * PROVISIONAL.
 */
export const BINARY_NONPRINTABLE_RATIO = 0.3;

/** Prefix length sampled when classifying a file as text or binary. */
export const BINARY_SNIFF_BYTES = 8192;

// ---------------------------------------------------------------------------
// Context modifiers — FAMILY 3's declared-purpose weighting
// ---------------------------------------------------------------------------

/**
 * Multipliers applied to capability signals according to what the package
 * claims to be. `child_process` in a build tool is its job; the same import in
 * a string-padding utility is an alarm.
 *
 * ## How the context is derived
 *
 * The analyser classifies a package into exactly one of these buckets, in
 * priority order, from metadata only — never from the code being judged, since
 * that would let an attacker talk their way out of a signal:
 *
 *   BUILD_TOOL    keywords/name/description match build, bundler, compiler,
 *                 cli, task-runner, test-runner, transpiler, linter
 *   SYSTEM        keywords match shell, exec, spawn, process, fs, filesystem,
 *                 daemon, native, binding
 *   NETWORK       keywords match http, client, request, fetch, socket, api,
 *                 rpc, websocket, server
 *   FRAMEWORK     keywords match framework, react, vue, angular, server-side
 *                 rendering; or the package has many dependents
 *   UTILITY       everything else, including a package with no keywords and no
 *                 description at all
 *
 * A package that declares nothing lands in UTILITY and is judged strictly,
 * which is the conservative direction: silence is not a defence.
 *
 * PROVISIONAL. The spread between UTILITY and BUILD_TOOL is what stops the
 * capability family from being pure noise, and is a phase 8 priority.
 */
export const CONTEXT_MODIFIERS = {
  BUILD_TOOL: 0.3,
  SYSTEM: 0.4,
  NETWORK: 0.6,
  FRAMEWORK: 0.8,
  UTILITY: 1.0,
} as const;

export type ContextBucket = keyof typeof CONTEXT_MODIFIERS;

/**
 * Dependent count at or above which a package is treated as FRAMEWORK for
 * context purposes, regardless of keywords. Widely depended-upon packages get
 * slightly more benefit of the doubt because their behaviour is more observed.
 *
 * PROVISIONAL.
 */
export const CONTEXT_FRAMEWORK_DEPENDENTS = 500;

/**
 * Floor on the context modifier after all adjustments. Context reduces a
 * signal's contribution; it must never erase it, or declaring the right
 * keywords would become an evasion technique.
 */
export const CONTEXT_MODIFIER_FLOOR = 0.25;

/**
 * Context modifiers apply to the capability family only. Install-time
 * execution, obfuscation, identity and provenance are not excused by what a
 * package claims to be: a build tool has no more business shipping a
 * Trojan-Source payload than a string utility does.
 */
export const CONTEXT_MODIFIED_FAMILIES = ['CAPABILITY'] as const;

// ---------------------------------------------------------------------------
// Confidence
// ---------------------------------------------------------------------------

/**
 * Confidence is a multiplier on weight, expressing how much the engine trusts a
 * hit — a rule that matched a full pattern in a file it parsed cleanly is worth
 * more than one that matched a substring in a file it could not parse.
 *
 * These are the floors and ceilings for that calculation.
 */
export const CONFIDENCE_MIN = 0.1;
export const CONFIDENCE_MAX = 1.0;

/** Confidence when a rule matched but the file could not be parsed as JS. */
export const CONFIDENCE_UNPARSED = 0.5;

/**
 * Bonus applied to overall confidence for each additional signal family that
 * fired. Corroboration across families is the strongest evidence the engine
 * has: obfuscation alone is a code-style choice, obfuscation plus a credential
 * read plus an install hook is an attack.
 *
 * PROVISIONAL.
 */
export const CONFIDENCE_CORROBORATION_BONUS = 0.08;

/**
 * Penalty applied to overall confidence for each analysis stage that failed or
 * was skipped. An analysis that could not reach the repository knows less than
 * one that could, and should say so rather than reporting a confident CLEAN.
 *
 * PROVISIONAL.
 */
export const CONFIDENCE_INCOMPLETENESS_PENALTY = 0.12;

// ---------------------------------------------------------------------------
// Verdict buckets
// ---------------------------------------------------------------------------

/**
 * Lower bounds of the weighted score for each verdict, checked highest first.
 *
 * The weighted score is Σ(weight × confidence × contextModifier) over fired
 * signals, where rule weights come from the seeded rule catalogue. Scores are
 * not normalised to a fixed range: a package can accumulate an arbitrarily high
 * score, and everything at or above the KNOWN_MALICIOUS floor is treated the
 * same.
 *
 * PROVISIONAL — these boundaries are the most consequential numbers in the
 * engine and the least defensible before corpus evaluation. Phase 8 fits them
 * against measured precision and recall per bucket.
 *
 * Note that KNOWN_MALICIOUS is not normally reached by score alone; it is
 * reserved for a corpus hash match or an explicit label, and the numeric floor
 * exists so that an overwhelming pile of evidence can still reach it.
 */
export const VERDICT_THRESHOLDS = {
  KNOWN_MALICIOUS: 100,
  LIKELY_MALICIOUS: 55,
  SUSPICIOUS: 28,
  LOW_RISK: 10,
  CLEAN: 0,
} as const;

/**
 * Verdict a hard trigger forces as a minimum, whatever the weighted score says.
 * Hard triggers encode behaviour that has no benign explanation; see
 * `HARD_TRIGGERS` in verdict.ts for the list.
 */
export const HARD_TRIGGER_MINIMUM_VERDICT = 'LIKELY_MALICIOUS' as const;

// ---------------------------------------------------------------------------
// Budgets — not detection thresholds, but tunable and better kept together
// ---------------------------------------------------------------------------

/** Whole-analysis wall-clock budget. Partial results are returned on expiry. */
export const ANALYSIS_BUDGET_MS = 90_000;

/** Per-family budget. One slow family must never consume the whole analysis. */
export const FAMILY_BUDGET_MS = 20_000;

/** Provenance does the most network work and gets a larger slice. */
export const PROVENANCE_BUDGET_MS = 35_000;

/**
 * Largest number of files handed to the AST parser. Beyond this the engine
 * samples rather than parsing everything, so a package with 9,000 tiny files
 * cannot exhaust the budget.
 */
export const MAX_PARSED_FILES = 1_500;

/** Largest single file handed to the AST parser. Bigger files are byte-scanned. */
export const MAX_PARSED_FILE_BYTES = 2 * 1024 * 1024;
