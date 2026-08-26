import {
  Activity,
  BookLock,
  Gauge,
  Layers,
  type LucideIcon,
  Package,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Siren,
} from 'lucide-react';

export interface NavItem {
  label: string;
  href: string;
  icon: LucideIcon;
  /** Match child routes as active too. Off for index routes that would swallow siblings. */
  matchPrefix?: boolean;
  description?: string;
}

export interface NavSection {
  label: string;
  items: NavItem[];
}

/**
 * Application navigation.
 *
 * The order mirrors the workflow: scan something, look at what came back, then
 * govern it.
 *
 * Every entry here must resolve to a route that exists. Next prefetches each
 * link in the viewport, so an entry pointing at an unbuilt route fires a 404 on
 * page load before anybody clicks anything — and when someone does click, a
 * demo turns into a broken link. The intelligence and integration surfaces
 * (feed, campaigns, corpus, rules, API keys, webhooks) are deliberately out of
 * scope for this build and are therefore not linked. Settings rejoins this list
 * when its pages exist, not before.
 */
export const NAV_SECTIONS: NavSection[] = [
  {
    label: 'Scanning',
    items: [
      { label: 'Dashboard', href: '/dashboard', icon: Gauge, description: 'Org-wide posture' },
      { label: 'New scan', href: '/scan', icon: Radar, description: 'Package or lockfile' },
      {
        label: 'Packages',
        href: '/packages',
        icon: Package,
        matchPrefix: true,
        description: 'Everything analysed',
      },
      {
        label: 'Analyses',
        href: '/analyses',
        icon: Activity,
        matchPrefix: true,
        description: 'History and queue',
      },
    ],
  },
  {
    label: 'Projects',
    items: [
      {
        label: 'Projects',
        href: '/projects',
        icon: Layers,
        matchPrefix: true,
        description: 'Dependency trees',
      },
    ],
  },
  {
    label: 'Policy',
    items: [
      {
        label: 'Policies',
        href: '/policies',
        icon: ShieldCheck,
        matchPrefix: true,
        description: 'Allow, warn, block',
      },
      { label: 'Violations', href: '/violations', icon: Siren, description: 'Triage inbox' },
      {
        label: 'Quarantine',
        href: '/quarantine',
        icon: ShieldAlert,
        description: 'Held for review',
      },
      { label: 'Exceptions', href: '/exceptions', icon: BookLock, description: 'Time-boxed' },
    ],
  },
];

/** Whether a nav item should render as the current page for a given pathname. */
export function isNavItemActive(item: NavItem, pathname: string): boolean {
  if (pathname === item.href) return true;
  if (!item.matchPrefix) return false;
  return pathname.startsWith(`${item.href}/`);
}
