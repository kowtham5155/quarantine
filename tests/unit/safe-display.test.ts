import { describe, expect, it } from 'vitest';

import {
  containsDeceptiveCharacters,
  safeText,
  shortHash,
  stripBidiControls,
} from '@/lib/safe-display';

describe('safeText', () => {
  it('strips bidi overrides used by Trojan Source', () => {
    const hostile = `react\u202Etxt.js`;
    expect(containsDeceptiveCharacters(hostile)).toBe(true);
    expect(stripBidiControls(hostile)).toBe('reacttxt.js');
  });

  it('strips zero-width characters used for homoglyph smuggling', () => {
    expect(stripBidiControls('lo\u200Bdash')).toBe('lodash');
  });

  it('collapses whitespace and bounds length', () => {
    expect(safeText('  a \n\n  b  ')).toBe('a b');
    expect(safeText('x'.repeat(50), { maxLength: 10 })).toHaveLength(10);
  });

  it('leaves an ordinary package name untouched', () => {
    expect(safeText('@scope/package-name')).toBe('@scope/package-name');
    expect(containsDeceptiveCharacters('@scope/package-name')).toBe(false);
  });
});

describe('shortHash', () => {
  it('keeps the leading digits and drops separators', () => {
    expect(shortHash('e3b0c44298fc1c149afbf4c8996fb924')).toBe('e3b0c44298fc');
  });
});
