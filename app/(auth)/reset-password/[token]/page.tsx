import type { Metadata } from 'next';
import Link from 'next/link';

import { ResetPasswordForm } from '@/app/(auth)/reset-password/[token]/ResetPasswordForm';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

export const metadata: Metadata = {
  title: 'Choose a new password',
  robots: { index: false, follow: false },
};

/**
 * The token is never validated here, only on submit.
 *
 * Checking it on GET would let anyone probe token validity with a bare request,
 * and would consume rate-limit budget on link previewers and mail scanners.
 */
export default async function ResetPasswordPage({
  params,
}: {
  params: Promise<{ token: string }>;
}) {
  const { token } = await params;

  // Tokens are 32 random bytes, base64url encoded.
  const plausible = /^[A-Za-z0-9_-]{20,200}$/.test(token);

  if (!plausible) {
    return (
      <Card>
        <CardHeader className="gap-1">
          <CardTitle className="text-xl">That link is not valid</CardTitle>
          <CardDescription>
            Reset links expire after one hour and can only be used once. Request a new one.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild className="w-full">
            <Link href="/forgot-password">Request a new link</Link>
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="gap-1">
        <CardTitle className="text-xl">Choose a new password</CardTitle>
        <CardDescription>
          Minimum 12 characters, and strong enough to survive an offline guessing attack.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ResetPasswordForm token={token} />
      </CardContent>
    </Card>
  );
}
