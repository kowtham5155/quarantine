import { Ecosystem } from '@prisma/client';

/**
 * URL construction for the package catalogue.
 *
 * Package names are attacker-controlled and may contain a scope separator
 * (`@scope/name`), a character that would otherwise split into two path
 * segments. Every link is therefore built through `encodeURIComponent` and read
 * back through `decodeURIComponent`, so `@types/node` lives at
 * `/packages/npm/%40types%2Fnode` and never escapes its segment.
 */

/** The lowercase ecosystem slug used in URLs. */
export type EcosystemSlug = 'npm' | 'pypi';

const SLUG_TO_ECOSYSTEM: Record<EcosystemSlug, Ecosystem> = {
  npm: Ecosystem.NPM,
  pypi: Ecosystem.PYPI,
};

const ECOSYSTEM_TO_SLUG: Record<Ecosystem, EcosystemSlug> = {
  [Ecosystem.NPM]: 'npm',
  [Ecosystem.PYPI]: 'pypi',
};

export function ecosystemSlug(ecosystem: Ecosystem): EcosystemSlug {
  return ECOSYSTEM_TO_SLUG[ecosystem];
}

/** Parse a URL segment into an ecosystem, or null when it names none. */
export function parseEcosystemSlug(value: string): Ecosystem | null {
  const slug = value.toLowerCase();
  return slug === 'npm' || slug === 'pypi' ? SLUG_TO_ECOSYSTEM[slug] : null;
}

/** Decode a dynamic route segment, tolerating one that is not valid encoding. */
export function decodeSegment(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export function packageHref(ecosystem: Ecosystem, name: string): string {
  return `/packages/${ecosystemSlug(ecosystem)}/${encodeURIComponent(name)}`;
}

export type VersionTab = 'report' | 'signals' | 'files' | 'provenance' | 'maintainers' | 'compare';

export function versionHref(
  ecosystem: Ecosystem,
  name: string,
  version: string,
  tab: VersionTab = 'report',
): string {
  const base = `${packageHref(ecosystem, name)}/${encodeURIComponent(version)}`;
  return tab === 'report' ? base : `${base}/${tab}`;
}

export function similarHref(ecosystem: Ecosystem, name: string): string {
  return `${packageHref(ecosystem, name)}/similar`;
}
