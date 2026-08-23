/**
 * Line diff used by provenance reporting (repository tag vs published tarball).
 *
 * Pure and synchronous so it can be unit tested and called from a server
 * component without a worker. Bounded on purpose: both sides come from
 * untrusted archives, so an adversarial pair of files must not be able to make
 * this allocate an unbounded matrix.
 */

export type DiffOp = 'equal' | 'insert' | 'delete';

export interface DiffLine {
  op: DiffOp;
  /** 1-based line number in the left/original text; null for inserted lines. */
  leftLine: number | null;
  /** 1-based line number in the right/modified text; null for deleted lines. */
  rightLine: number | null;
  content: string;
}

export interface DiffResult {
  lines: DiffLine[];
  added: number;
  removed: number;
  /**
   * True when the inputs exceeded the alignment budget and were compared
   * coarsely (every differing line reported as a delete followed by an insert)
   * instead of being aligned line by line.
   */
  truncated: boolean;
}

/** Largest region we will run quadratic alignment over, per side. */
const ALIGNMENT_BUDGET = 1500;

function splitLines(text: string): string[] {
  if (text === '') return [];
  return text.replace(/\r\n?/g, '\n').split('\n');
}

/** Longest common subsequence table over two bounded line arrays. */
function alignLcs(left: string[], right: string[]): DiffLine[] {
  const n = left.length;
  const m = right.length;
  const width = m + 1;
  const table = new Uint32Array((n + 1) * width);

  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      table[i * width + j] =
        left[i] === right[j]
          ? (table[(i + 1) * width + (j + 1)] ?? 0) + 1
          : Math.max(table[(i + 1) * width + j] ?? 0, table[i * width + (j + 1)] ?? 0);
    }
  }

  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;

  while (i < n && j < m) {
    if (left[i] === right[j]) {
      out.push({ op: 'equal', leftLine: i + 1, rightLine: j + 1, content: left[i] ?? '' });
      i++;
      j++;
    } else if ((table[(i + 1) * width + j] ?? 0) >= (table[i * width + (j + 1)] ?? 0)) {
      out.push({ op: 'delete', leftLine: i + 1, rightLine: null, content: left[i] ?? '' });
      i++;
    } else {
      out.push({ op: 'insert', leftLine: null, rightLine: j + 1, content: right[j] ?? '' });
      j++;
    }
  }

  while (i < n) {
    out.push({ op: 'delete', leftLine: i + 1, rightLine: null, content: left[i] ?? '' });
    i++;
  }
  while (j < m) {
    out.push({ op: 'insert', leftLine: null, rightLine: j + 1, content: right[j] ?? '' });
    j++;
  }

  return out;
}

/** Coarse fallback for inputs past the alignment budget. */
function alignCoarse(
  left: string[],
  right: string[],
  leftOffset: number,
  rightOffset: number,
): DiffLine[] {
  const out: DiffLine[] = [];
  const max = Math.max(left.length, right.length);

  for (let index = 0; index < max; index++) {
    const l = left[index];
    const r = right[index];
    if (l !== undefined && r !== undefined && l === r) {
      out.push({
        op: 'equal',
        leftLine: leftOffset + index + 1,
        rightLine: rightOffset + index + 1,
        content: l,
      });
      continue;
    }
    if (l !== undefined) {
      out.push({
        op: 'delete',
        leftLine: leftOffset + index + 1,
        rightLine: null,
        content: l,
      });
    }
    if (r !== undefined) {
      out.push({
        op: 'insert',
        leftLine: null,
        rightLine: rightOffset + index + 1,
        content: r,
      });
    }
  }

  return out;
}

/** Diff two texts line by line. */
export function diffLines(leftText: string, rightText: string): DiffResult {
  const left = splitLines(leftText);
  const right = splitLines(rightText);

  // Trim the identical head and tail first — in provenance diffing most of the
  // file is usually unchanged, and this is what keeps the matrix small.
  let prefix = 0;
  while (prefix < left.length && prefix < right.length && left[prefix] === right[prefix]) {
    prefix++;
  }

  let suffix = 0;
  while (
    suffix < left.length - prefix &&
    suffix < right.length - prefix &&
    left[left.length - 1 - suffix] === right[right.length - 1 - suffix]
  ) {
    suffix++;
  }

  const head: DiffLine[] = [];
  for (let index = 0; index < prefix; index++) {
    head.push({
      op: 'equal',
      leftLine: index + 1,
      rightLine: index + 1,
      content: left[index] ?? '',
    });
  }

  const leftMiddle = left.slice(prefix, left.length - suffix);
  const rightMiddle = right.slice(prefix, right.length - suffix);

  const overBudget = leftMiddle.length > ALIGNMENT_BUDGET || rightMiddle.length > ALIGNMENT_BUDGET;

  const middle = overBudget
    ? alignCoarse(leftMiddle, rightMiddle, prefix, prefix)
    : alignLcs(leftMiddle, rightMiddle).map((line) => ({
        ...line,
        leftLine: line.leftLine === null ? null : line.leftLine + prefix,
        rightLine: line.rightLine === null ? null : line.rightLine + prefix,
      }));

  const tail: DiffLine[] = [];
  for (let index = 0; index < suffix; index++) {
    const leftLine = left.length - suffix + index;
    const rightLine = right.length - suffix + index;
    tail.push({
      op: 'equal',
      leftLine: leftLine + 1,
      rightLine: rightLine + 1,
      content: left[leftLine] ?? '',
    });
  }

  const lines = [...head, ...middle, ...tail];

  return {
    lines,
    added: lines.filter((line) => line.op === 'insert').length,
    removed: lines.filter((line) => line.op === 'delete').length,
    truncated: overBudget,
  };
}

export interface CollapseOptions {
  /** Unchanged lines kept on either side of a change. */
  context?: number;
}

export type DiffChunk = { kind: 'lines'; lines: DiffLine[] } | { kind: 'gap'; hiddenCount: number };

/** Collapse long runs of unchanged lines into gap markers. */
export function collapseUnchanged(
  lines: readonly DiffLine[],
  options: CollapseOptions = {},
): DiffChunk[] {
  const context = options.context ?? 3;
  const keep = new Array<boolean>(lines.length).fill(false);

  lines.forEach((line, index) => {
    if (line.op === 'equal') return;
    for (let offset = -context; offset <= context; offset++) {
      const target = index + offset;
      if (target >= 0 && target < lines.length) keep[target] = true;
    }
  });

  const chunks: DiffChunk[] = [];
  let buffer: DiffLine[] = [];
  let hidden = 0;

  const flushLines = () => {
    if (buffer.length > 0) {
      chunks.push({ kind: 'lines', lines: buffer });
      buffer = [];
    }
  };
  const flushGap = () => {
    if (hidden > 0) {
      chunks.push({ kind: 'gap', hiddenCount: hidden });
      hidden = 0;
    }
  };

  lines.forEach((line, index) => {
    if (keep[index]) {
      flushGap();
      buffer.push(line);
    } else {
      flushLines();
      hidden++;
    }
  });

  flushLines();
  flushGap();

  return chunks;
}
