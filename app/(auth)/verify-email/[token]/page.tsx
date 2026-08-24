import type { Metadata } from 'next';
import Link from 'next/link';
import { headers } from 'next/headers';
import { CircleCheck, CircleX } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { verifyEmail } from '@/lib/services/auth.service';

export const metadata: Metadata = {
  title: 'Verify your email',
  robots: { index: false, follow: false },
};

/**
 * Verification is a GET because that is what a link in an email is.
 *
 * The token is single-use and consumed here; `dynamic = 'force-dynamic'` keeps
 * Next from caching the result and handing the same page to the next visitor.
 */
export const dynamic = 'force-dynamic';

export default async function VerifyEmailPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;

  const headerList = await headers();
  const forwarded = headerList.get('x-forwarded-for');

  const result = await verifyEmail(token, {
    ip: forwarded ? (forwarded.split(',')[0]?.trim() ?? null) : null,
    userAgent: headerList.get('user-agent'),
  });

  if (!result.ok) {
    return (
      <Card>
        <CardHeader className="gap-2">
          <div className="flex items-center gap-2">
            <CircleX aria-hidden="true" className="size-5 text-destructive" />
            <CardTitle className="text-xl">That link is not valid</CardTitle>
          </div>
          <CardDescription>
            Verification links expire after one hour and can only be used once. Sign in and we will
            send you a fresh one.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild className="w-full">
            <Link href="/login">Go to sign in</Link>
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="gap-2">
        <div className="flex items-center gap-2">
          <CircleCheck aria-hidden="true" className="size-5 text-verdict-clean-accent" />
          <CardTitle className="text-xl">Email verified</CardTitle>
        </div>
        <CardDescription>
          <span className="font-mono">{result.email}</span> is confirmed. You can sign in now.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Button asChild className="w-full">
          <Link href="/login?verified=1">Continue to sign in</Link>
        </Button>
      </CardContent>
    </Card>
  );
}
