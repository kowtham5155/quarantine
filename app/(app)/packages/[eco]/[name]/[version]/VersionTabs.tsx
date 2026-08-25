'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

import { cn } from '@/lib/utils';

export interface VersionTabsProps {
  base: string;
  /** Rendered next to the tab label, e.g. the number of signals that fired. */
  counts?: Partial<Record<string, number>>;
}

const TABS = [
  { id: 'report', label: 'Report', href: '' },
  { id: 'signals', label: 'Signals', href: '/signals' },
  { id: 'files', label: 'Files', href: '/files' },
  { id: 'provenance', label: 'Provenance', href: '/provenance' },
  { id: 'maintainers', label: 'Maintainers', href: '/maintainers' },
  { id: 'compare', label: 'Compare', href: '/compare' },
] as const;

/** Tab navigation for one version's report. Real links, so each tab is a URL. */
export function VersionTabs({ base, counts = {} }: VersionTabsProps) {
  const pathname = usePathname();

  return (
    <nav
      aria-label="Report sections"
      className="-mb-px flex gap-1 overflow-x-auto border-b border-border"
    >
      {TABS.map((tab) => {
        const href = `${base}${tab.href}`;
        const active = tab.href === '' ? pathname === base : pathname === href;
        const count = counts[tab.id];

        return (
          <Link
            key={tab.id}
            href={href}
            aria-current={active ? 'page' : undefined}
            className={cn(
              'flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-2 text-sm whitespace-nowrap transition-colors',
              active
                ? 'border-primary font-medium text-foreground'
                : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {tab.label}
            {typeof count === 'number' ? (
              <span className="rounded bg-muted px-1.5 py-px font-mono text-[10px] text-muted-foreground tabular-nums">
                {count}
              </span>
            ) : null}
          </Link>
        );
      })}
    </nav>
  );
}
