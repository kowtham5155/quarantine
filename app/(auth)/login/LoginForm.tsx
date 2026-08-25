'use client';

import { useActionState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { KeyRound, Loader2, ShieldCheck } from 'lucide-react';

import { loginAction } from '@/app/(auth)/actions';
import { initialLoginState } from '@/app/(auth)/form-states';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

/**
 * Two-step sign-in.
 *
 * Step one posts the password. If the account has a second factor the action
 * comes back with `step: 'totp'` and the credentials are carried forward in
 * hidden fields, so the browser re-submits them with the code rather than the
 * server holding half-authenticated state between requests.
 */
export function LoginForm({ next, notice }: { next?: string; notice?: string }) {
  const [state, formAction, pending] = useActionState(loginAction, initialLoginState);
  const totpInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (state.step === 'totp') totpInputRef.current?.focus();
  }, [state.step]);

  const carried = state.data ?? {};
  const fieldErrors = state.fieldErrors ?? {};

  return (
    <form action={formAction} className="space-y-5" noValidate>
      {next ? <input type="hidden" name="next" value={next} /> : null}

      {notice ? (
        <Alert>
          <ShieldCheck aria-hidden="true" className="size-4" />
          <AlertTitle>{notice}</AlertTitle>
        </Alert>
      ) : null}

      {state.status === 'error' && state.message ? (
        <Alert variant="destructive" role="alert">
          <AlertTitle>Sign-in failed</AlertTitle>
          <AlertDescription>{state.message}</AlertDescription>
        </Alert>
      ) : null}

      {state.step === 'password' ? (
        <>
          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              name="email"
              type="email"
              autoComplete="username"
              inputMode="email"
              required
              autoFocus
              defaultValue={carried.email ?? ''}
              aria-invalid={Boolean(fieldErrors.email)}
              aria-describedby={fieldErrors.email ? 'email-error' : undefined}
            />
            {fieldErrors.email ? (
              <p id="email-error" className="text-sm text-destructive">
                {fieldErrors.email.join(' ')}
              </p>
            ) : null}
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label htmlFor="password">Password</Label>
              <Link
                href="/forgot-password"
                className="text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
              >
                Forgot password?
              </Link>
            </div>
            <Input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              aria-invalid={Boolean(fieldErrors.password)}
            />
          </div>
        </>
      ) : (
        <>
          <input type="hidden" name="email" value={carried.email ?? ''} />
          <input type="hidden" name="password" value={carried.password ?? ''} />

          <div className="rounded-md border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
            <p className="flex items-center gap-2 font-medium text-foreground">
              <KeyRound aria-hidden="true" className="size-4" />
              Two-factor authentication
            </p>
            <p className="mt-1">
              Enter the 6-digit code from your authenticator app, or one of your recovery codes.
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="totp">Verification code</Label>
            <Input
              ref={totpInputRef}
              id="totp"
              name="totp"
              type="text"
              inputMode="text"
              autoComplete="one-time-code"
              maxLength={20}
              required
              className="font-mono tracking-[0.3em]"
              placeholder="000000"
            />
          </div>
        </>
      )}

      <Button type="submit" className="w-full" disabled={pending}>
        {pending ? <Loader2 aria-hidden="true" className="size-4 animate-spin" /> : null}
        {state.step === 'totp' ? 'Verify and sign in' : 'Sign in'}
      </Button>

      <p className="text-center text-sm text-muted-foreground">
        No account?{' '}
        <Link href="/register" className="text-foreground underline underline-offset-4">
          Create one
        </Link>
      </p>
    </form>
  );
}
