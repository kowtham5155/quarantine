import type { Metadata } from 'next';
import Link from 'next/link';
import { CircleX, Users } from 'lucide-react';

import { AcceptInviteForm } from '@/app/(auth)/accept-invite/[token]/AcceptInviteForm';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { getAuthContext } from '@/lib/auth-context';
import { safeText } from '@/lib/safe-display';
import { previewInvite } from '@/lib/services/org.service';

export const metadata: Metadata = {
  title: 'Accept your invitation',
  robots: { index: false, follow: false },
};

export const dynamic = 'force-dynamic';

export default async function AcceptInvitePage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;

  const invite = await previewInvite(token);

  if (!invite) {
    return (
      <Card>
        <CardHeader className="gap-2">
          <div className="flex items-center gap-2">
            <CircleX aria-hidden="true" className="size-5 text-destructive" />
            <CardTitle className="text-xl">That invitation is not valid</CardTitle>
          </div>
          <CardDescription>
            It may have expired, already been accepted, or been replaced by a newer one. Ask an
            administrator to send another.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild variant="outline" className="w-full">
            <Link href="/login">Go to sign in</Link>
          </Button>
        </CardContent>
      </Card>
    );
  }

  const orgName = safeText(invite.orgName, { maxLength: 80 });
  const ctx = await getAuthContext();

  return (
    <Card>
      <CardHeader className="gap-2">
        <div className="flex items-center gap-2">
          <Users aria-hidden="true" className="size-5 text-primary" />
          <CardTitle className="text-xl">Join {orgName}</CardTitle>
        </div>
        <CardDescription>
          This invitation was sent to <span className="font-mono">{invite.email}</span> and can only
          be accepted by that account.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-5">
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
          <dt className="text-muted-foreground">Organisation</dt>
          <dd className="font-medium">{orgName}</dd>
          <dt className="text-muted-foreground">Role</dt>
          <dd>
            <Badge variant="secondary" className="font-mono text-xs">
              {invite.role}
            </Badge>
          </dd>
          <dt className="text-muted-foreground">Expires</dt>
          <dd>
            <time dateTime={invite.expiresAt.toISOString()}>
              {invite.expiresAt.toISOString().slice(0, 10)}
            </time>
          </dd>
        </dl>

        {!ctx ? (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Sign in as <span className="font-mono">{invite.email}</span> to accept, or create that
              account first.
            </p>
            <div className="flex flex-col gap-2 sm:flex-row">
              <Button asChild className="flex-1">
                <Link
                  href={`/login?invite=1&next=${encodeURIComponent(`/accept-invite/${token}`)}`}
                >
                  Sign in
                </Link>
              </Button>
              <Button asChild variant="outline" className="flex-1">
                <Link href="/register">Create an account</Link>
              </Button>
            </div>
          </div>
        ) : ctx.email.toLowerCase() !== invite.email.toLowerCase() ? (
          <div className="space-y-3">
            <p className="text-sm text-destructive">
              You are signed in as <span className="font-mono">{ctx.email}</span>, but this
              invitation is for <span className="font-mono">{invite.email}</span>.
            </p>
            <Button asChild variant="outline" className="w-full">
              <Link href="/api/auth/signout">Sign out and switch account</Link>
            </Button>
          </div>
        ) : (
          <AcceptInviteForm token={token} orgName={orgName} />
        )}
      </CardContent>
    </Card>
  );
}
