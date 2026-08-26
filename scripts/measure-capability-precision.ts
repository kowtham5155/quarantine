/**
 * Measure Q-CAP-001's precision against real published npm code.
 *
 * Ground truth is computed independently of the rule: a package "genuinely
 * reaches for process execution" when an AST walk finds `child_process` being
 * loaded anywhere in it. That is the definition the original measurement used,
 * so these numbers are comparable to it — with one correction.
 *
 * The correction: ground truth must not care what the loader is *called*.
 * Bundled code routinely renames `require` — rolldown ships
 * `__require("child_process")` from a `createRequire` — and a ground truth that
 * only recognises the identifier `require` scores such a package as a false
 * positive when the rule catches it. It was the rule that was right. Any call
 * taking `child_process` as its string-literal argument counts here, whatever
 * the callee is named.
 *
 * The corpus is this project's own `node_modules` — real, published, installed
 * code. Nothing is executed, imported or installed: every file is parsed and
 * walked, and that is all.
 *
 *     npx tsx scripts/measure-capability-precision.ts
 */
import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';

import {
  collectCalls,
  collectImports,
  collectMemberExpressions,
  parseSource,
} from '../lib/engine/ast';

const ROOT = path.resolve(process.cwd(), 'node_modules');

/** Bounds, so one enormous package cannot dominate the run. */
const MAX_FILES_PER_PACKAGE = 60;
const MAX_BYTES_PER_FILE = 2 * 1024 * 1024;

const EXEC_MEMBER = /\.(?:execSync|exec|spawnSync|spawn|fork|execFile|execFileSync)$/;

/**
 * The variants under test. Each decides whether a flattened member expression
 * (`re.exec`, `cp.execSync`, `child_process.exec`) should fire Q-CAP-001 on its
 * own, with no `child_process` import to back it up.
 */
const VARIANTS: Array<{ id: string; label: string; matches: (text: string) => boolean }> = [
  {
    id: 'A',
    label: 'original — any exec-family member',
    matches: (text) => EXEC_MEMBER.test(text),
  },
  {
    id: 'B',
    label: 'drop bare `exec`',
    matches: (text) => /\.(?:execSync|spawnSync|spawn|fork|execFile|execFileSync)$/.test(text),
  },
  {
    id: 'C',
    label: 'drop bare `exec` and `fork`',
    matches: (text) => /\.(?:execSync|spawnSync|spawn|execFile|execFileSync)$/.test(text),
  },
  {
    id: 'D',
    label: 'shipped — receiver-gated `exec` and `fork`',
    matches: (text) => {
      if (/\.(?:execSync|spawnSync|spawn|execFile|execFileSync)$/.test(text)) return true;
      if (/\.fork$/.test(text)) return /child_?process|^cp\.|^proc\./i.test(text);
      if (!/\.exec$/.test(text)) return false;
      const receiver = text.slice(0, -'.exec'.length);
      return /(?:^|\.)(?:child_process|childProcess|cp|proc|process)$/i.test(receiver);
    },
  },
];

const EXEC_MODULES = new Set(['child_process', 'node:child_process']);

async function jsFiles(dir: string, depth = 0): Promise<string[]> {
  if (depth > 4) return [];

  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }

  const out: string[] = [];
  for (const entry of entries) {
    if (out.length >= MAX_FILES_PER_PACKAGE) break;
    const full = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === '.bin') continue;
      out.push(...(await jsFiles(full, depth + 1)));
      continue;
    }

    if (/\.(?:js|cjs|mjs)$/.test(entry.name)) out.push(full);
  }

  return out.slice(0, MAX_FILES_PER_PACKAGE);
}

async function packageDirs(): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(ROOT, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name === '.bin') continue;

    if (entry.name.startsWith('@')) {
      const scope = path.join(ROOT, entry.name);
      for (const inner of await readdir(scope, { withFileTypes: true })) {
        if (inner.isDirectory()) out.push(path.join(scope, inner.name));
      }
      continue;
    }

    out.push(path.join(ROOT, entry.name));
  }
  return out;
}

interface Tally {
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
}

const tallies = new Map<string, Tally>(
  VARIANTS.map((variant) => [
    variant.id,
    { truePositives: 0, falsePositives: 0, falseNegatives: 0 },
  ]),
);

const falsePositiveExamples = new Map<string, string[]>(VARIANTS.map((v) => [v.id, []]));

let scanned = 0;
let importing = 0;

for (const dir of await packageDirs()) {
  const files = await jsFiles(dir);
  if (files.length === 0) continue;

  scanned += 1;

  let importsChildProcess = false;
  const members: string[] = [];

  for (const file of files) {
    let source: string;
    try {
      const info = await stat(file);
      if (info.size > MAX_BYTES_PER_FILE) continue;
      source = await readFile(file, 'utf8');
    } catch {
      continue;
    }

    const parsed = parseSource(file, source);
    if (!parsed.parsed) continue;

    for (const record of collectImports(parsed)) {
      if (EXEC_MODULES.has(record.source)) importsChildProcess = true;
    }
    // Renamed loaders: `__require('child_process')`, `createRequire(...)(...)`.
    for (const call of collectCalls(parsed)) {
      const first = call.args[0];
      if (typeof first === 'string' && EXEC_MODULES.has(first)) importsChildProcess = true;
    }
    for (const member of collectMemberExpressions(parsed)) {
      if (EXEC_MEMBER.test(member.text)) members.push(member.text);
    }
  }

  if (importsChildProcess) importing += 1;

  for (const variant of VARIANTS) {
    // Q-CAP-001 fires on the import path or on the member fallback; only the
    // fallback differs between variants.
    const fires = importsChildProcess || members.some((text) => variant.matches(text));
    const tally = tallies.get(variant.id)!;

    if (fires && importsChildProcess) tally.truePositives += 1;
    else if (fires) {
      tally.falsePositives += 1;
      const examples = falsePositiveExamples.get(variant.id)!;
      if (examples.length < 12) examples.push(path.relative(ROOT, dir));
    } else if (importsChildProcess) tally.falseNegatives += 1;
  }
}

console.log(`packages scanned                        ${scanned}`);
console.log(`packages loading child_process          ${importing}\n`);
console.log('  variant                                      TP   FP   FN  precision  recall');

for (const variant of VARIANTS) {
  const { truePositives, falsePositives, falseNegatives } = tallies.get(variant.id)!;
  const precision = truePositives / Math.max(1, truePositives + falsePositives);
  const recall = truePositives / Math.max(1, truePositives + falseNegatives);
  console.log(
    `  ${variant.id}  ${variant.label.padEnd(42)}${String(truePositives).padStart(3)}  ` +
      `${String(falsePositives).padStart(3)}  ${String(falseNegatives).padStart(3)}  ` +
      `${precision.toFixed(3).padStart(9)}  ${recall.toFixed(3).padStart(6)}`,
  );
}

for (const variant of VARIANTS) {
  const examples = falsePositiveExamples.get(variant.id)!;
  if (examples.length > 0) {
    console.log(`\n  ${variant.id} false positives: ${examples.join(', ')}`);
  }
}
