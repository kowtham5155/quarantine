'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { useTheme } from 'next-themes';
import { LogOut, Menu, Moon, Radar, Search, Sun } from 'lucide-react';

import { Sidebar } from '@/components/shared/Sidebar';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from '@/components/ui/sheet';
import { safeText } from '@/lib/safe-display';
import { cn } from '@/lib/utils';

export interface TopBarUser {
  name: string;
  email: string;
  /** Org the session is currently scoped to. */
  orgName?: string;
  role?: string;
}

export interface TopBarProps {
  user?: TopBarUser;
  /** Opens the command palette. Wired up by the shell that owns the palette. */
  onOpenSearch?: () => void;
  className?: string;
}

function initialsOf(name: string): string {
  const parts = name.trim().split(/\s+/).slice(0, 2);
  const letters = parts.map((part) => part[0] ?? '').join('');
  return (letters || '?').toUpperCase();
}

function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  // Theme is only known after hydration; render a stable icon until then.
  useEffect(() => setMounted(true), []);

  const isDark = !mounted || resolvedTheme !== 'light';

  return (
    <Button
      variant="ghost"
      size="icon"
      aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
      onClick={() => setTheme(isDark ? 'light' : 'dark')}
    >
      {isDark ? <Moon aria-hidden="true" /> : <Sun aria-hidden="true" />}
    </Button>
  );
}

/** Application header: mobile nav trigger, search, theme, account menu. */
export function TopBar({ user, onOpenSearch, className }: TopBarProps) {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const displayName = user ? safeText(user.name, { maxLength: 64 }) : null;

  return (
    <header
      className={cn(
        'sticky top-0 z-40 flex h-14 items-center gap-2 border-b border-border bg-background/80 px-3 backdrop-blur sm:px-4',
        className,
      )}
    >
      <Sheet open={mobileNavOpen} onOpenChange={setMobileNavOpen}>
        <SheetTrigger asChild>
          <Button variant="ghost" size="icon" className="lg:hidden" aria-label="Open navigation">
            <Menu aria-hidden="true" />
          </Button>
        </SheetTrigger>
        <SheetContent side="left" className="w-72 p-0">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <Sidebar onNavigate={() => setMobileNavOpen(false)} />
        </SheetContent>
      </Sheet>

      <Button
        variant="outline"
        size="sm"
        onClick={onOpenSearch}
        className="hidden w-full max-w-xs justify-start gap-2 text-muted-foreground sm:flex"
      >
        <Search aria-hidden="true" />
        <span>Search packages…</span>
        <kbd className="ml-auto rounded bg-muted px-1.5 py-0.5 font-mono text-[10px]">⌘K</kbd>
      </Button>

      <Button
        variant="ghost"
        size="icon"
        onClick={onOpenSearch}
        aria-label="Search packages"
        className="sm:hidden"
      >
        <Search aria-hidden="true" />
      </Button>

      <div className="ml-auto flex items-center gap-1">
        <Button asChild size="sm" className="hidden sm:inline-flex">
          <Link href="/scan">
            <Radar aria-hidden="true" />
            New scan
          </Link>
        </Button>

        <ThemeToggle />

        {user && displayName ? (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" aria-label="Account menu">
                <Avatar className="size-7">
                  <AvatarFallback className="text-[11px]">{initialsOf(displayName)}</AvatarFallback>
                </Avatar>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-60">
              <DropdownMenuLabel className="flex flex-col gap-0.5">
                <span className="truncate text-sm font-medium">{displayName}</span>
                <span className="truncate text-xs font-normal text-muted-foreground">
                  {safeText(user.email, { maxLength: 128 })}
                </span>
                {user.orgName ? (
                  <span className="truncate text-xs font-normal text-muted-foreground">
                    {safeText(user.orgName, { maxLength: 64 })}
                    {user.role ? ` · ${user.role.toLowerCase()}` : ''}
                  </span>
                ) : null}
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              {/* Profile and Settings items lived here pointing at /settings and
                  /settings/profile. Neither route exists, so both were a 404 on
                  click; they belong back here once there is a settings area to
                  point at. Sign out went to /logout, which does not exist
                  either — the route Auth.js actually serves is
                  /api/auth/signout, which is what the onboarding and
                  accept-invite headers already use. */}
              <DropdownMenuItem asChild>
                <Link href="/api/auth/signout">
                  <LogOut aria-hidden="true" />
                  Sign out
                </Link>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        ) : (
          <Button asChild variant="ghost" size="sm">
            <Link href="/login">Sign in</Link>
          </Button>
        )}
      </div>
    </header>
  );
}
