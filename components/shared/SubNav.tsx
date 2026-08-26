'use client';

import Link from 'next/link';
import { usePathname, useSearchParams } from 'next/navigation';

import { cn } from '@/lib/utils';

export interface SubNavItem {
  label: string;
  href: string;
  /** Rendered as a small count chip next to the label. */
  count?: number;
  /** Match child routes as active too. */
  matchPrefix?: boolean;
}

export interface SubNavProps {
  items: readonly SubNavItem[];
  ariaLabel: string;
  className?: string;
}

/**
 * Which item is the page being viewed?
 *
 * The query string counts, not just the path: a set of tabs that filters one
 * route — `/violations?state=OPEN` — shares a pathname across every tab, so
 * comparing paths alone would light all of them at once. An item carrying no
 * query of its own is the unfiltered view, and is current only when none of the
 * keys its siblings filter on are set.
 */
function activeHref(
  items: readonly SubNavItem[],
  pathname: string,
  search: URLSearchParams,
): string | null {
  const filterKeys = new Set<string>();
  for (const item of items) {
    const query = item.href.split('?')[1];
    if (query) for (const key of new URLSearchParams(query).keys()) filterKeys.add(key);
  }

  for (const item of items) {
    const [path = '', query = ''] = item.href.split('?');

    if (path !== pathname) {
      if (item.matchPrefix === true && pathname.startsWith(`${path}/`)) return item.href;
      continue;
    }

    const wanted = [...new URLSearchParams(query)];

    if (wanted.length === 0) {
      if ([...filterKeys].every((key) => search.get(key) === null)) return item.href;
      continue;
    }

    if (wanted.every(([key, value]) => search.get(key) === value)) return item.href;
  }

  return null;
}

/**
 * Tab-style navigation for a section with sub-pages. Real links, so every tab
 * is a URL that can be bookmarked, shared and opened in a new tab — a set of
 * client-side panels would lose all three.
 */
export function SubNav({ items, ariaLabel, className }: SubNavProps) {
  const pathname = usePathname();
  const search = useSearchParams();
  const current = activeHref(items, pathname, search);

  return (
    <nav
      aria-label={ariaLabel}
      className={cn('-mb-px flex gap-1 overflow-x-auto border-b border-border', className)}
    >
      {items.map((item) => {
        const active = item.href === current;

        return (
          <Link
            key={item.href}
            href={item.href}
            aria-current={active ? 'page' : undefined}
            className={cn(
              'flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-2 text-sm whitespace-nowrap transition-colors',
              active
                ? 'border-primary font-medium text-foreground'
                : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {item.label}
            {typeof item.count === 'number' ? (
              <span className="rounded bg-muted px-1.5 py-px font-mono text-[10px] text-muted-foreground tabular-nums">
                {item.count}
              </span>
            ) : null}
          </Link>
        );
      })}
    </nav>
  );
}
