import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * Every literal internal link must point at a route that exists.
 *
 * Three dead links shipped without anyone noticing: the user menu's Sign out
 * went to `/logout` and Profile and Settings went to `/settings*`, none of
 * which are routes. Nothing failed, because no test relates a href to the file
 * tree. This does.
 *
 * Only literal hrefs are checked. A template literal is built at runtime and
 * its shape is the route helpers' job — see routes.test.ts.
 */

const ROOT = join(__dirname, '..', '..');
const APP = join(ROOT, 'app');

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

/** `app/(app)/projects/[id]/page.tsx` -> `/projects/[id]` */
function routeForFile(file: string): string | null {
  const rel = relative(APP, file).split('\\').join('/');
  if (!/\/(page|route)\.tsx?$/.test(rel)) return null;
  const segments = rel
    .replace(/\/(page|route)\.tsx?$/, '')
    .split('/')
    .filter((s) => s.length > 0 && !(s.startsWith('(') && s.endsWith(')')));
  return `/${segments.join('/')}`;
}

const routes = walk(APP)
  .map(routeForFile)
  .filter((r): r is string => r !== null);

function matches(href: string, route: string): boolean {
  const h = href.split('/').filter(Boolean);
  const r = route.split('/').filter(Boolean);

  for (let i = 0; i < r.length; i++) {
    const segment = r[i]!;
    if (segment.startsWith('[...')) return h.length >= i;
    if (segment.startsWith('[')) {
      if (h[i] === undefined) return false;
      continue;
    }
    if (h[i] !== segment) return false;
  }
  return h.length === r.length;
}

const sources = [...walk(APP), ...walk(join(ROOT, 'components'))].filter((f) => f.endsWith('.tsx'));

const LITERAL_HREF = /href=["'](\/[^"'{}$\s]*)["']/g;

const links: Array<{ href: string; where: string }> = [];
for (const file of sources) {
  const text = readFileSync(file, 'utf8');
  text.split('\n').forEach((line, index) => {
    for (const match of line.matchAll(LITERAL_HREF)) {
      const href = match[1]!.split('?')[0]!.split('#')[0]!;
      if (href === '/' || href.length === 0) continue;
      links.push({ href, where: `${relative(ROOT, file)}:${index + 1}` });
    }
  });
}

describe('internal link targets', () => {
  it('finds links to check', () => {
    expect(links.length).toBeGreaterThan(10);
  });

  it('every literal href resolves to a route that exists', () => {
    const dead = links
      .filter(({ href }) => !routes.some((route) => matches(href, route)))
      .map(({ href, where }) => `${href}  (${where})`);

    expect(dead).toEqual([]);
  });
});
