/**
 * Vocabulary shared by the analysis engine and the UI: the verdict scale and
 * the six signal families.
 *
 * Tailwind class strings are written out in full rather than composed at
 * runtime — the scanner only sees literals, so anything interpolated would be
 * dropped from the build.
 */

export const VERDICTS = [
  'KNOWN_MALICIOUS',
  'LIKELY_MALICIOUS',
  'SUSPICIOUS',
  'LOW_RISK',
  'CLEAN',
] as const;

export type Verdict = (typeof VERDICTS)[number];

export interface VerdictMeta {
  label: string;
  /** Short sentence shown under a verdict on report pages. */
  description: string;
  /** Ordering for sorts and charts — 0 is worst. */
  rank: number;
  /** Solid fill treatment. */
  solidClass: string;
  /** Tinted treatment with a coloured border, used for inline badges. */
  subtleClass: string;
  /** Text-only treatment for use directly on the page background. */
  textClass: string;
  /** Raw hex, for Recharts and anything that cannot take a class. */
  hex: string;
}

export const VERDICT_META: Record<Verdict, VerdictMeta> = {
  KNOWN_MALICIOUS: {
    label: 'Known malicious',
    description: 'Matches a confirmed malicious package or a known-bad code fingerprint.',
    rank: 0,
    solidClass: 'bg-verdict-known-malicious text-verdict-known-malicious-foreground',
    subtleClass:
      'bg-verdict-known-malicious-surface text-verdict-known-malicious-accent border-verdict-known-malicious-accent/40',
    textClass: 'text-verdict-known-malicious-accent',
    hex: '#991b1b',
  },
  LIKELY_MALICIOUS: {
    label: 'Likely malicious',
    description: 'Hard triggers fired. Do not install; treat any prior install as a compromise.',
    rank: 1,
    solidClass: 'bg-verdict-likely-malicious text-verdict-likely-malicious-foreground',
    subtleClass:
      'bg-verdict-likely-malicious-surface text-verdict-likely-malicious-accent border-verdict-likely-malicious-accent/40',
    textClass: 'text-verdict-likely-malicious-accent',
    hex: '#dc2626',
  },
  SUSPICIOUS: {
    label: 'Suspicious',
    description: 'Multiple families corroborate. Review the flagged evidence before installing.',
    rank: 2,
    solidClass: 'bg-verdict-suspicious text-verdict-suspicious-foreground',
    subtleClass:
      'bg-verdict-suspicious-surface text-verdict-suspicious-accent border-verdict-suspicious-accent/40',
    textClass: 'text-verdict-suspicious-accent',
    hex: '#ea580c',
  },
  LOW_RISK: {
    label: 'Low risk',
    description: 'Minor signals fired, none corroborated. Usually benign but worth a glance.',
    rank: 3,
    solidClass: 'bg-verdict-low-risk text-verdict-low-risk-foreground',
    subtleClass:
      'bg-verdict-low-risk-surface text-verdict-low-risk-accent border-verdict-low-risk-accent/40',
    textClass: 'text-verdict-low-risk-accent',
    hex: '#ca8a04',
  },
  CLEAN: {
    label: 'Clean',
    description: 'No signal fired across all six families on a complete analysis.',
    rank: 4,
    solidClass: 'bg-verdict-clean text-verdict-clean-foreground',
    subtleClass:
      'bg-verdict-clean-surface text-verdict-clean-accent border-verdict-clean-accent/40',
    textClass: 'text-verdict-clean-accent',
    hex: '#059669',
  },
};

export const SIGNAL_FAMILIES = [
  'INSTALL',
  'OBFUSCATION',
  'CAPABILITY',
  'TYPOSQUAT',
  'MAINTAINER',
  'PROVENANCE',
] as const;

export type SignalFamily = (typeof SIGNAL_FAMILIES)[number];

export interface SignalFamilyMeta {
  label: string;
  /** Rule ID prefix, e.g. Q-INS-001. */
  prefix: string;
  description: string;
  subtleClass: string;
  dotClass: string;
  hex: string;
}

export const SIGNAL_FAMILY_META: Record<SignalFamily, SignalFamilyMeta> = {
  INSTALL: {
    label: 'Install-time execution',
    prefix: 'Q-INS',
    description: 'Lifecycle scripts and what they reach for while npm is still running.',
    subtleClass: 'bg-signal-install-surface text-signal-install border-signal-install/40',
    dotClass: 'bg-signal-install',
    hex: '#f43f5e',
  },
  OBFUSCATION: {
    label: 'Obfuscation & evasion',
    prefix: 'Q-OBF',
    description: 'Entropy, encoded payloads, dynamic evaluation and Trojan Source characters.',
    subtleClass:
      'bg-signal-obfuscation-surface text-signal-obfuscation border-signal-obfuscation/40',
    dotClass: 'bg-signal-obfuscation',
    hex: '#14b8a6',
  },
  CAPABILITY: {
    label: 'Dangerous capability',
    prefix: 'Q-CAP',
    description: 'Process, socket and credential access weighted against the declared purpose.',
    subtleClass: 'bg-signal-capability-surface text-signal-capability border-signal-capability/40',
    dotClass: 'bg-signal-capability',
    hex: '#f59e0b',
  },
  TYPOSQUAT: {
    label: 'Identity & typosquatting',
    prefix: 'Q-TYP',
    description: 'Edit distance, homoglyphs, separator tricks and dependency-confusion posture.',
    subtleClass: 'bg-signal-typosquat-surface text-signal-typosquat border-signal-typosquat/40',
    dotClass: 'bg-signal-typosquat',
    hex: '#06b6d4',
  },
  MAINTAINER: {
    label: 'Maintainer & release forensics',
    prefix: 'Q-MNT',
    description: 'Dormancy breaks, fresh maintainers and release cadence anomalies.',
    subtleClass: 'bg-signal-maintainer-surface text-signal-maintainer border-signal-maintainer/40',
    dotClass: 'bg-signal-maintainer',
    hex: '#84cc16',
  },
  PROVENANCE: {
    label: 'Provenance & integrity',
    prefix: 'Q-PRV',
    description: 'Tarball-versus-source diffing, binary blobs and attestation coverage.',
    subtleClass: 'bg-signal-provenance-surface text-signal-provenance border-signal-provenance/40',
    dotClass: 'bg-signal-provenance',
    hex: '#6366f1',
  },
};

export const SIGNAL_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
export type SignalSeverity = (typeof SIGNAL_SEVERITIES)[number];

/**
 * Categorical series colours, in fixed assignment order — never cycled, never
 * reassigned when a filter changes the series count.
 *
 * Validated against both surfaces (#09090b dark, #ffffff light) for the
 * lightness band, chroma floor, colour-vision separation (worst adjacent pair
 * ΔE 12.5 protan, well above the 8 target) and 3:1 contrast. The verdict and
 * signal-family palettes are *status* and *identity* colours respectively and
 * are exempt from this ordering — they always ship with a text label, so colour
 * is never the only channel.
 */
export const SERIES_COLORS = ['#3b82f6', '#0d9488', '#d97706'] as const;

/** Series colour for "flagged" counts plotted beside a neutral total. */
export const FLAGGED_SERIES_COLOR = '#ea580c';

/** Recessive grid and axis ink for charts, matching the border token. */
export const CHART_GRID_COLOR = 'var(--border)';

/** Ordering helper: worst verdict first. */
export function compareVerdicts(a: Verdict, b: Verdict): number {
  return VERDICT_META[a].rank - VERDICT_META[b].rank;
}

export function isVerdict(value: unknown): value is Verdict {
  return typeof value === 'string' && (VERDICTS as readonly string[]).includes(value);
}

export function isSignalFamily(value: unknown): value is SignalFamily {
  return typeof value === 'string' && (SIGNAL_FAMILIES as readonly string[]).includes(value);
}
