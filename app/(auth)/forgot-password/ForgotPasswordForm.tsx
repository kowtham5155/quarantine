'use client';

import { useActionState } from 'react';
import Link from 'next/link';
import { Loader2, MailCheck } from 'lucide-react';

import { forgotPasswordAction, initialForgotPasswordState } from '@/app/(auth)/actions';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

export function ForgotPasswordForm() {
  const [state, formAction, pending] = useActionState(
    forgotPasswordAction,
    initialForgotPasswordState,
  );

  if (state.status === 'success') {
    return (
      <div className="space-y-5">
        <Alert>
          <MailCheck aria-hidden="true" className="size-4" />
          <AlertTitle>Check your email</AlertTitle>
          <AlertDescription>{state.message}</AlertDescription>
        </Alert>

        {state.resetToken ? (
          <div className="rounded-md border border-dashed border-border p-3 text-sm">
            <p className="font-medium">Development shortcut</p>
            <p className="mt-1 text-muted-foreground">
              No mail provider is configured outside production, so the link is shown here instead.
            </p>
            <Link
              href={`/reset-password/${state.resetToken}`}
              className="mt-2 inline-block font-mono text-xs break-all text-primary underline underline-offset-4"
            >
              /reset-password/{state.resetToken}
            </Link>
          </div>
        ) : null}

        <Button asChild variant="outline" className="w-full">
          <Link href="/login">Back to sign in</Link>
        </Button>
      </div>
    );
  }

  return (
    <form action={formAction} className="space-y-5" noValidate>
      {state.status === 'error' && state.message ? (
        <Alert variant="destructive" role="alert">
          <AlertTitle>Could not send the link</AlertTitle>
          <AlertDescription>{state.message}</AlertDescription>
        </Alert>
      ) : null}

      <div className="space-y-2">
        <Label htmlFor="email">Email</Label>
        <Input
          id="email"
          name="email"
          type="email"
          inputMode="email"
          autoComplete="username"
          required
          autoFocus
        />
      </div>

      <Button type="submit" className="w-full" disabled={pending}>
        {pending ? <Loader2 aria-hidden="true" className="size-4 animate-spin" /> : null}
        Send reset link
      </Button>

      <p className="text-center text-sm text-muted-foreground">
        Remembered it?{' '}
        <Link href="/login" className="text-foreground underline underline-offset-4">
          Sign in
        </Link>
      </p>
    </form>
  );
}
