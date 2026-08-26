import { parse } from '@babel/parser';
import type { File, Node } from '@babel/types';

import { MAX_PARSED_FILE_BYTES } from '@/lib/engine/thresholds';

/**
 * Static parsing of untrusted JavaScript and TypeScript.
 *
 * ## THE SAFETY RULE
 *
 * `@babel/parser` builds a syntax tree. It does not evaluate, and this module
 * gives it nothing else to work with: no `vm`, no `Function`, no `eval`, no
 * `require`. A file that reaches here is a string, and it leaves as a tree of
 * plain objects. There is deliberately no "just run it in a sandbox to see what
 * it does" path anywhere in the engine — sandboxes escape, and a static
 * analyser that never executes cannot be escaped from.
 *
 * ## Parsing hostile input
 *
 * Malware is frequently syntactically broken, deliberately or otherwise:
 * truncated payloads, mixed module systems, invented syntax to confuse tools.
 * Two things help, and it is worth being precise about how far each goes.
 *
 * `errorRecovery: true` recovers from errors Babel can carry on past — a
 * reserved word used as an identifier, a duplicate declaration, a stray `await`
 * — and still returns a tree with `ast.errors` populated. It does **not**
 * recover from structural damage: an unclosed paren, an unterminated string or
 * a truncated function body yields no tree at all. Measured, not assumed.
 *
 * When both the module and script attempts fail, `parsed` is false and `ast` is
 * null. That is not a dead end: every signal module that matters degrades to
 * byte-level scanning of `source`, reports its hits at `CONFIDENCE_UNPARSED`,
 * and marks the file `UNPARSEABLE`. Deliberately corrupting a file therefore
 * lowers the engine's confidence but does not blind it, which is the property
 * that actually needs to hold.
 */

export interface ParsedFile {
  path: string;
  source: string;
  ast: File | null;
  /** True when the parser produced a tree, even a partial one. */
  parsed: boolean;
  /** Recovered syntax errors. A non-empty list with `parsed` true is normal. */
  errors: string[];
  /** Byte offset of the start of each line, for offset-to-line conversion. */
  lineOffsets: number[];
}

/**
 * Babel 8 enables most of what used to need a plugin (class fields, optional
 * chaining, dynamic import, top-level await) by default, and removed
 * `importAssertions` in favour of import attributes. Only the syntaxes that are
 * still genuinely optional are listed.
 */
const BABEL_PLUGINS = [
  'jsx',
  'typescript',
  ['decorators', { decoratorsBeforeExport: true }],
  'exportDefaultFrom',
  'importAttributes',
] as const;

/** Byte offsets at which each line begins, so a node can be located cheaply. */
function computeLineOffsets(source: string): number[] {
  const offsets = [0];
  for (let index = 0; index < source.length; index++) {
    if (source[index] === '\n') offsets.push(index + 1);
  }
  return offsets;
}

/**
 * Parse a source file. Never throws: an unparseable file is a fact about the
 * package, not an error in the analyser, and the byte-level rules still apply
 * to it.
 */
export function parseSource(filePath: string, source: string): ParsedFile {
  const lineOffsets = computeLineOffsets(source);

  if (source.length > MAX_PARSED_FILE_BYTES) {
    return {
      path: filePath,
      source,
      ast: null,
      parsed: false,
      errors: ['File exceeds the parse size limit.'],
      lineOffsets,
    };
  }

  const attempt = (sourceType: 'module' | 'script'): ParsedFile | null => {
    try {
      const ast = parse(source, {
        sourceType,
        errorRecovery: true,
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true,
        allowSuperOutsideMethod: true,
        allowUndeclaredExports: true,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- the plugin tuple is wider than the exported union
        plugins: BABEL_PLUGINS as any,
      });

      return {
        path: filePath,
        source,
        ast,
        parsed: true,
        errors: (ast.errors ?? []).map((error) =>
          typeof error === 'string' ? error : ((error as { message?: string }).message ?? 'error'),
        ),
        lineOffsets,
      };
    } catch {
      return null;
    }
  };

  // Most package code is ESM or parses identically either way; a CommonJS file
  // using `with` or a bare `return` only parses as a script.
  const result = attempt('module') ?? attempt('script');

  return (
    result ?? {
      path: filePath,
      source,
      ast: null,
      parsed: false,
      errors: ['Could not be parsed as JavaScript or TypeScript.'],
      lineOffsets,
    }
  );
}

/** 1-indexed line number for a byte offset. Binary search over line starts. */
export function lineForOffset(lineOffsets: number[], offset: number): number {
  let low = 0;
  let high = lineOffsets.length - 1;

  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    const start = lineOffsets[mid];
    if (start !== undefined && start <= offset) low = mid;
    else high = mid - 1;
  }

  return low + 1;
}

// ---------------------------------------------------------------------------
// Walking
// ---------------------------------------------------------------------------

type Visitor = (node: Node, ancestors: Node[]) => void;

/**
 * Depth-first walk with an explicit stack.
 *
 * Recursion is avoided on purpose: a deliberately deep expression tree — say
 * ten thousand nested string concatenations, which is exactly what an
 * obfuscator emits — overflows the call stack, and a crash in the analyser is a
 * denial of service on the whole scan. An explicit stack has no such limit.
 */
export function walk(root: Node, visit: Visitor): void {
  const stack: Array<{ node: Node; ancestors: Node[] }> = [{ node: root, ancestors: [] }];

  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) break;

    const { node, ancestors } = current;
    visit(node, ancestors);

    const childAncestors = [...ancestors, node];

    for (const key of Object.keys(node)) {
      // `loc` and `range` hold position data, not children; skipping them
      // avoids walking a lot of objects that can never match anything.
      if (key === 'loc' || key === 'range' || key === 'leadingComments') continue;

      const value = (node as unknown as Record<string, unknown>)[key];

      if (Array.isArray(value)) {
        for (const item of value) {
          if (isNode(item)) stack.push({ node: item, ancestors: childAncestors });
        }
      } else if (isNode(value)) {
        stack.push({ node: value, ancestors: childAncestors });
      }
    }
  }
}

function isNode(value: unknown): value is Node {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { type?: unknown }).type === 'string'
  );
}

// ---------------------------------------------------------------------------
// Extraction helpers
// ---------------------------------------------------------------------------

export interface ImportRecord {
  /** The module specifier, e.g. `child_process`. */
  source: string;
  /** `import`, `require`, or `import()`. */
  kind: 'import' | 'require' | 'dynamic';
  line: number;
}

/** Every module this file pulls in, however it does it. */
export function collectImports(file: ParsedFile): ImportRecord[] {
  if (!file.ast) return [];
  const imports: ImportRecord[] = [];

  walk(file.ast, (node) => {
    if (node.type === 'ImportDeclaration' && node.source.type === 'StringLiteral') {
      imports.push({
        source: node.source.value,
        kind: 'import',
        line: lineForOffset(file.lineOffsets, node.start ?? 0),
      });
      return;
    }

    if (node.type === 'CallExpression') {
      const callee = node.callee;
      const firstArg = node.arguments[0];

      const isRequire = callee.type === 'Identifier' && callee.name === 'require';
      const isDynamic = callee.type === 'Import';

      if ((isRequire || isDynamic) && firstArg?.type === 'StringLiteral') {
        imports.push({
          source: firstArg.value,
          kind: isDynamic ? 'dynamic' : 'require',
          line: lineForOffset(file.lineOffsets, node.start ?? 0),
        });
      }
    }
  });

  return imports;
}

export interface CallRecord {
  /** Dotted callee text, e.g. `child_process.exec` or `eval`. */
  callee: string;
  /** String-literal arguments, in order. Non-literals appear as null. */
  args: Array<string | null>;
  line: number;
  node: Node;
}

/** Every call expression, with its callee flattened to a dotted string. */
export function collectCalls(file: ParsedFile): CallRecord[] {
  if (!file.ast) return [];
  const calls: CallRecord[] = [];

  walk(file.ast, (node) => {
    if (node.type !== 'CallExpression' && node.type !== 'NewExpression') return;

    const callee = calleeText(node.callee as Node);
    if (!callee) return;

    calls.push({
      callee,
      args: (node.arguments ?? []).map((argument) =>
        argument.type === 'StringLiteral' ? argument.value : null,
      ),
      line: lineForOffset(file.lineOffsets, node.start ?? 0),
      node,
    });
  });

  return calls;
}

/** Flatten `a.b.c` to `"a.b.c"`. Computed members become `[]`. */
export function calleeText(node: Node): string | null {
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'Import') return 'import';
  if (node.type === 'Super') return 'super';
  if (node.type === 'ThisExpression') return 'this';

  if (node.type === 'MemberExpression') {
    const object = calleeText(node.object as Node);
    if (!object) return null;

    if (node.computed) {
      if (node.property.type === 'StringLiteral') return `${object}.${node.property.value}`;
      return `${object}[]`;
    }

    if (node.property.type === 'Identifier') return `${object}.${node.property.name}`;
    return null;
  }

  return null;
}

export interface MemberRecord {
  text: string;
  line: number;
}

/** Every member expression, flattened. Used for `process.env` style patterns. */
export function collectMemberExpressions(file: ParsedFile): MemberRecord[] {
  if (!file.ast) return [];
  const members: MemberRecord[] = [];

  walk(file.ast, (node) => {
    if (node.type !== 'MemberExpression') return;
    const text = calleeText(node);
    if (text) members.push({ text, line: lineForOffset(file.lineOffsets, node.start ?? 0) });
  });

  return members;
}

export interface StringRecord {
  value: string;
  line: number;
  /** Length in characters, before any truncation for display. */
  length: number;
}

/** Every string literal and template chunk. Hostile content by definition. */
/**
 * Byte ranges covered by comments, so a rule can tell code from prose.
 *
 * Needed because a dotted quad in a comment is usually not an address. core-js
 * annotates its modules with ECMAScript spec section numbers — `25.4.3.1` is
 * the Promise constructor — and those are indistinguishable from an IPv4
 * address by shape alone. Position is what separates them.
 */
export function collectCommentRanges(file: ParsedFile): Array<[number, number]> {
  const comments = file.ast?.comments;
  if (!comments) return [];

  const ranges: Array<[number, number]> = [];
  for (const comment of comments) {
    if (typeof comment.start === 'number' && typeof comment.end === 'number') {
      ranges.push([comment.start, comment.end]);
    }
  }
  return ranges;
}

/** Is this byte offset inside one of those ranges? */
export function isInsideRanges(ranges: ReadonlyArray<[number, number]>, offset: number): boolean {
  for (const [start, end] of ranges) {
    if (offset >= start && offset < end) return true;
  }
  return false;
}

export function collectStrings(file: ParsedFile): StringRecord[] {
  if (!file.ast) return [];
  const strings: StringRecord[] = [];

  walk(file.ast, (node) => {
    if (node.type === 'StringLiteral') {
      strings.push({
        value: node.value,
        line: lineForOffset(file.lineOffsets, node.start ?? 0),
        length: node.value.length,
      });
      return;
    }

    if (node.type === 'TemplateElement') {
      const raw = node.value.cooked ?? node.value.raw;
      strings.push({
        value: raw,
        line: lineForOffset(file.lineOffsets, node.start ?? 0),
        length: raw.length,
      });
    }
  });

  return strings;
}

/**
 * Depth of a binary `+` chain rooted at this node.
 *
 * Iterative for the same reason `walk` is: obfuscated identifier construction
 * routinely nests hundreds deep, and measuring it must not be what crashes.
 */
export function concatenationDepth(node: Node): number {
  let depth = 0;
  const stack: Array<{ node: Node; depth: number }> = [{ node, depth: 1 }];

  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) break;

    depth = Math.max(depth, current.depth);

    if (current.node.type === 'BinaryExpression' && current.node.operator === '+') {
      stack.push({ node: current.node.left as Node, depth: current.depth + 1 });
      stack.push({ node: current.node.right as Node, depth: current.depth + 1 });
    }
  }

  return depth;
}

/** String array literals, for the obfuscator lookup-table pattern. */
export function collectStringArrays(file: ParsedFile): Array<{ members: string[]; line: number }> {
  if (!file.ast) return [];
  const arrays: Array<{ members: string[]; line: number }> = [];

  walk(file.ast, (node) => {
    if (node.type !== 'ArrayExpression') return;

    const members: string[] = [];
    let allStrings = true;

    for (const element of node.elements) {
      if (element?.type === 'StringLiteral') members.push(element.value);
      else {
        allStrings = false;
        break;
      }
    }

    if (allStrings && members.length > 0) {
      arrays.push({ members, line: lineForOffset(file.lineOffsets, node.start ?? 0) });
    }
  });

  return arrays;
}

// ---------------------------------------------------------------------------
// Excerpts
// ---------------------------------------------------------------------------

/**
 * A short slice of source around a line, for display in a report.
 *
 * HOSTILE INPUT. The return value is verbatim package content. It is length
 * capped here so a single-line 40MB payload cannot be pasted into a report, but
 * it still must be escaped by whatever renders it.
 */
export function excerptAt(source: string, line: number, maxChars = 200): string {
  const lines = source.split('\n');
  const target = lines[line - 1] ?? '';
  const trimmed = target.trim();
  return trimmed.length > maxChars ? `${trimmed.slice(0, maxChars - 1)}…` : trimmed;
}
