import { Ecosystem } from '@prisma/client';
import { describe, expect, it } from 'vitest';

import {
  decodeSegment,
  ecosystemSlug,
  packageHref,
  parseEcosystemSlug,
  similarHref,
  versionHref,
} from '@/lib/routes';

describe('package route helpers', () => {
  it('keeps a scoped name inside a single path segment', () => {
    expect(packageHref(Ecosystem.NPM, '@types/node')).toBe('/packages/npm/%40types%2Fnode');
    expect(decodeSegment('%40types%2Fnode')).toBe('@types/node');
  });

  it('encodes versions too, so a tag with a slash cannot split the path', () => {
    expect(versionHref(Ecosystem.NPM, 'left-pad', '1.3.0')).toBe('/packages/npm/left-pad/1.3.0');
    expect(versionHref(Ecosystem.NPM, 'left-pad', '1.3.0', 'signals')).toBe(
      '/packages/npm/left-pad/1.3.0/signals',
    );
    expect(versionHref(Ecosystem.PYPI, 'requests', '2.31.0/x')).toBe(
      '/packages/pypi/requests/2.31.0%2Fx',
    );
  });

  it('round-trips the ecosystem slug', () => {
    expect(ecosystemSlug(Ecosystem.NPM)).toBe('npm');
    expect(ecosystemSlug(Ecosystem.PYPI)).toBe('pypi');
    expect(parseEcosystemSlug('NPM')).toBe(Ecosystem.NPM);
    expect(parseEcosystemSlug('pypi')).toBe(Ecosystem.PYPI);
    expect(parseEcosystemSlug('crates')).toBeNull();
  });

  it('does not throw on a malformed percent escape', () => {
    expect(decodeSegment('%E0%A4%A')).toBe('%E0%A4%A');
  });

  it('builds the typosquat neighbourhood link', () => {
    expect(similarHref(Ecosystem.NPM, 'lodahs')).toBe('/packages/npm/lodahs/similar');
  });
});
