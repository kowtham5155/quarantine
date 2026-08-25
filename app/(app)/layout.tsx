import type { ReactNode } from 'react';
import { redirect } from 'next/navigation';

import { AppShell } from '@/components/shared/AppShell';
import { getAuthContext, getSessionIdentity } from '@/lib/auth-context';
import * as orgService from '@/lib/services/org.service';

/**
 * Shell for every signed-in route.
 *
 * Middleware has already bounced visitors with no session cookie, but that is a
 * redirect and not an authorisation decision (CLAUDE.md rule 3): the context is
 * resolved from the database here, and a session whose membership has since been
 * revoked lands back on the login page rather than inside the application.
 *
 * A signed-in user with no organisation is sent to onboarding — that is not an
 * error, it is the state right after registering.
 */
export default async function AppLayout({ children }: { children: ReactNode }) {
  const ctx = await getAuthContext();

  if (!ctx) {
    const identity = await getSessionIdentity();
    redirect(identity ? '/onboarding' : '/login');
  }

  const org = await orgService.getCurrent({ ...ctx, actorEmail: ctx.email });

  return (
    <AppShell
      user={{
        name: ctx.name,
        email: ctx.email,
        orgName: org.name,
        role: ctx.role,
      }}
    >
      {children}
    </AppShell>
  );
}
