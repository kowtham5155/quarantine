import {
  Activity,
  BookLock,
  Boxes,
  FileSearch,
  FlaskConical,
  Gauge,
  KeyRound,
  Layers,
  type LucideIcon,
  Network,
  Package,
  Radar,
  ScrollText,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Webhook,
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
 * Application navigation. The order mirrors the workflow: scan something, look
 * at what came back, govern it, then investigate ecosystem-wide.
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
  {
    label: 'Intelligence',
    items: [
      { label: 'Feed', href: '/feed', icon: Network, description: 'Newly flagged, 24h' },
      {
        label: 'Campaigns',
        href: '/campaigns',
        icon: Boxes,
        matchPrefix: true,
        description: 'Clustered families',
      },
      {
        label: 'Corpus',
        href: '/corpus',
        icon: FlaskConical,
        matchPrefix: true,
        description: 'Labelled evaluation set',
      },
      {
        label: 'Rules',
        href: '/rules',
        icon: ScrollText,
        matchPrefix: true,
        description: 'Catalogue and weights',
      },
    ],
  },
  {
    label: 'Integrations',
    items: [
      { label: 'Overview', href: '/integrations', icon: FileSearch },
      { label: 'API keys', href: '/integrations/api-keys', icon: KeyRound },
      { label: 'Webhooks', href: '/integrations/webhooks', icon: Webhook },
    ],
  },
  {
    label: 'Organisation',
    items: [{ label: 'Settings', href: '/settings', icon: Settings, matchPrefix: true }],
  },
];

/** Whether a nav item should render as the current page for a given pathname. */
export function isNavItemActive(item: NavItem, pathname: string): boolean {
  if (pathname === item.href) return true;
  if (!item.matchPrefix) return false;
  return pathname.startsWith(`${item.href}/`);
}
