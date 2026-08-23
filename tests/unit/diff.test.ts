import { describe, expect, it } from 'vitest';

import { collapseUnchanged, diffLines } from '@/lib/diff';

describe('diffLines', () => {
  it('reports no changes for identical input', () => {
    const result = diffLines('a\nb\nc', 'a\nb\nc');
    expect(result.added).toBe(0);
    expect(result.removed).toBe(0);
    expect(result.lines.every((line) => line.op === 'equal')).toBe(true);
  });

  it('detects an inserted line and numbers both sides', () => {
    const result = diffLines('a\nc', 'a\nb\nc');
    expect(result.added).toBe(1);
    expect(result.removed).toBe(0);

    const inserted = result.lines.find((line) => line.op === 'insert');
    expect(inserted?.content).toBe('b');
    expect(inserted?.leftLine).toBeNull();
    expect(inserted?.rightLine).toBe(2);
  });

  it('treats a file absent from the left as wholly added', () => {
    const result = diffLines('', 'require("child_process").exec(payload)');
    expect(result.removed).toBe(0);
    expect(result.added).toBe(1);
  });

  it('collapses long unchanged runs into gaps', () => {
    const left = Array.from({ length: 40 }, (_, i) => `line ${i}`).join('\n');
    const right = left.replace('line 20', 'line 20 // injected');

    const chunks = collapseUnchanged(diffLines(left, right).lines, { context: 2 });
    expect(chunks.some((chunk) => chunk.kind === 'gap')).toBe(true);
  });
});
