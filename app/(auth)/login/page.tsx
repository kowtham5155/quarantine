import type { Metadata } from 'next';

import { LoginForm } from '@/app/(auth)/login/LoginForm';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { safeText } from '@/lib/safe-display';

export const metadata: Metadata = {
  title: 'Sign in',
  description: 'Sign in to Quarantine.',
  robots: { index: false, follow: false },
};

const NOTICES: Record<string, string> = {
  reset: 'Password updated. Sign in with your new password.',
  invite: 'Sign in to accept your invitation.',
};

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;

  const rawNext = params.next;
  const next =
    typeof rawNext === 'string' && rawNext.startsWith('/') && !rawNext.startsWith('//')
      ? rawNext
      : undefined;

  let notice: string | undefined;
  if (params.reset) notice = NOTICES.reset;
  else if (params.invite) notice = NOTICES.invite;

  return (
    <Card>
      <CardHeader className="gap-1">
        <CardTitle className="text-xl">Sign in</CardTitle>
        <CardDescription>Continue to your Quarantine workspace.</CardDescription>
      </CardHeader>
      <CardContent>
        <LoginForm
          {...(next ? { next: safeText(next, { maxLength: 200 }) } : {})}
          {...(notice ? { notice } : {})}
        />
      </CardContent>
    </Card>
  );
}
