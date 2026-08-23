'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ShieldCheck } from 'lucide-react';

import { NAV_SECTIONS, isNavItemActive } from '@/components/shared/nav-config';
import { ScrollArea } from '@/components/ui/scroll-area';
import { cn } from '@/lib/utils';

export interface SidebarProps {
  /** Called after a link is chosen — used to close the mobile sheet. */
  onNavigate?: () => void;
  className?: string;
}

/** Primary navigation. Rendered fixed on desktop and inside a sheet on mobile. */
export function Sidebar({ onNavigate, className }: SidebarProps) {
  const pathname = usePathname();

  return (
    <div className={cn('flex h-full flex-col bg-sidebar', className)}>
      <div className="flex h-14 shrink-0 items-center gap-2 border-b border-sidebar-border px-4">
        <Link
          href="/dashboard"
          onClick={onNavigate}
          className="flex items-center gap-2 font-semibold tracking-tight"
        >
          <ShieldCheck aria-hidden="true" className="size-5 text-primary" />
          <span>Quarantine</span>
        </Link>
      </div>

      <ScrollArea className="flex-1">
        <nav aria-label="Primary" className="flex flex-col gap-5 px-3 py-4">
          {NAV_SECTIONS.map((section) => (
            <div key={section.label} className="flex flex-col gap-1">
              <h2 className="px-2 pb-1 text-[11px] font-semibold tracking-wider text-muted-foreground uppercase">
                {section.label}
              </h2>
              <ul className="flex flex-col gap-0.5">
                {section.items.map((item) => {
                  const active = isNavItemActive(item, pathname);
                  const Icon = item.icon;
                  return (
                    <li key={item.href}>
                      <Link
                        href={item.href}
                        onClick={onNavigate}
                        aria-current={active ? 'page' : undefined}
                        className={cn(
                          'group flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition-colors',
                          active
                            ? 'bg-sidebar-accent font-medium text-sidebar-accent-foreground'
                            : 'text-sidebar-foreground hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground',
                        )}
                      >
                        <Icon
                          aria-hidden="true"
                          className={cn(
                            'size-4 shrink-0',
                            active ? 'text-sidebar-primary' : 'text-muted-foreground',
                          )}
                        />
                        <span className="truncate">{item.label}</span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </nav>
      </ScrollArea>

      <div className="border-t border-sidebar-border px-4 py-3 text-[11px] text-muted-foreground">
        Static analysis only. Package contents are never executed.
      </div>
    </div>
  );
}
