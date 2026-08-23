'use client';

import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { useRouter } from 'next/navigation';

import { Sidebar } from '@/components/shared/Sidebar';
import { TopBar, type TopBarUser } from '@/components/shared/TopBar';
import { NAV_SECTIONS } from '@/components/shared/nav-config';
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command';
import { cn } from '@/lib/utils';

export interface AppShellProps {
  children: ReactNode;
  user?: TopBarUser;
  /** Constrain the content column. Wide pages (dependency trees) opt out. */
  fullWidth?: boolean;
  className?: string;
}

/**
 * Authenticated application layout: fixed sidebar on large screens, sheet-based
 * navigation below `lg`, and a command palette on ⌘K / Ctrl+K.
 */
export function AppShell({ children, user, fullWidth = false, className }: AppShellProps) {
  const router = useRouter();
  const [paletteOpen, setPaletteOpen] = useState(false);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key.toLowerCase() === 'k' && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, []);

  const go = useCallback(
    (href: string) => {
      setPaletteOpen(false);
      router.push(href);
    },
    [router],
  );

  return (
    <div className="flex min-h-svh bg-background">
      <aside className="hidden w-64 shrink-0 border-r border-border lg:block">
        <div className="sticky top-0 h-svh">
          <Sidebar />
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar user={user} onOpenSearch={() => setPaletteOpen(true)} />

        <main
          id="main"
          className={cn(
            'w-full flex-1 px-4 py-6 sm:px-6 lg:px-8',
            fullWidth ? '' : 'mx-auto max-w-7xl',
            className,
          )}
        >
          {children}
        </main>
      </div>

      <CommandDialog
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        title="Command palette"
        description="Jump to a page or start a scan"
      >
        <CommandInput placeholder="Jump to…" />
        <CommandList>
          <CommandEmpty>No matches.</CommandEmpty>
          {NAV_SECTIONS.map((section) => (
            <CommandGroup key={section.label} heading={section.label}>
              {section.items.map((item) => {
                const Icon = item.icon;
                return (
                  <CommandItem
                    key={item.href}
                    value={`${section.label} ${item.label} ${item.href}`}
                    onSelect={() => go(item.href)}
                  >
                    <Icon aria-hidden="true" />
                    <span>{item.label}</span>
                    {item.description ? (
                      <span className="ml-auto text-xs text-muted-foreground">
                        {item.description}
                      </span>
                    ) : null}
                  </CommandItem>
                );
              })}
            </CommandGroup>
          ))}
        </CommandList>
      </CommandDialog>
    </div>
  );
}
