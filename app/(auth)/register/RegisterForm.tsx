'use client';

import { useActionState, useState } from 'react';
import Link from 'next/link';
import { Loader2, MailCheck } from 'lucide-react';

import { registerAction } from '@/app/(auth)/actions';
import { initialRegisterState } from '@/app/(auth)/form-states';
import { PasswordStrength } from '@/app/(auth)/register/PasswordStrength';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

export function RegisterForm() {
  const [state, formAction, pending] = useActionState(registerAction, initialRegisterState);
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');

  const fieldErrors = state.fieldErrors ?? {};

  if (state.status === 'success' && state.registeredEmail) {
    return (
      <div className="space-y-5">
        <Alert>
          <MailCheck aria-hidden="true" className="size-4" />
          <AlertTitle>Your account is ready</AlertTitle>
          <AlertDescription>
            {/* Deliberately does not claim an email was sent. This deployment has
                no mail transport, and signing in does not require verification —
                telling someone to check an inbox nothing was sent to is the kind
                of small lie that costs a user ten minutes and their trust. */}
            If that address could be registered,{' '}
            <span className="font-mono">{state.registeredEmail}</span> can sign in now. Email
            verification is not wired up in this deployment, so there is nothing waiting in your
            inbox and nothing you need to click.
          </AlertDescription>
        </Alert>

        {state.verificationToken ? (
          <div className="rounded-md border border-dashed border-border p-3 text-sm">
            <p className="font-medium">Development shortcut</p>
            <p className="mt-1 text-muted-foreground">
              No mail provider is configured, so the verification link is shown here instead. It
              marks the address verified; it is not needed to sign in.
            </p>
            <Link
              href={`/verify-email/${state.verificationToken}`}
              className="mt-2 inline-block font-mono text-xs break-all text-primary underline underline-offset-4"
            >
              /verify-email/{state.verificationToken}
            </Link>
          </div>
        ) : null}

        <Button asChild variant="outline" className="w-full">
          <Link href="/login">Sign in</Link>
        </Button>
      </div>
    );
  }

  return (
    <form action={formAction} className="space-y-5" noValidate>
      {state.status === 'error' && state.message ? (
        <Alert variant="destructive" role="alert">
          <AlertTitle>Could not create the account</AlertTitle>
          <AlertDescription>{state.message}</AlertDescription>
        </Alert>
      ) : null}

      <div className="space-y-2">
        <Label htmlFor="name">Name</Label>
        <Input
          id="name"
          name="name"
          type="text"
          autoComplete="name"
          required
          autoFocus
          value={name}
          onChange={(event) => setName(event.target.value)}
          aria-invalid={Boolean(fieldErrors.name)}
          aria-describedby={fieldErrors.name ? 'name-error' : undefined}
        />
        {fieldErrors.name ? (
          <p id="name-error" className="text-sm text-destructive">
            {fieldErrors.name.join(' ')}
          </p>
        ) : null}
      </div>

      <div className="space-y-2">
        <Label htmlFor="email">Work email</Label>
        <Input
          id="email"
          name="email"
          type="email"
          inputMode="email"
          autoComplete="username"
          required
          value={email}
          onChange={(event) => setEmail(event.target.value)}
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
        <Label htmlFor="password">Password</Label>
        <Input
          id="password"
          name="password"
          type="password"
          autoComplete="new-password"
          required
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          aria-invalid={Boolean(fieldErrors.password)}
          aria-describedby="password-strength"
        />
        <div id="password-strength">
          <PasswordStrength password={password} userInputs={[email, name]} />
        </div>
        {fieldErrors.password ? (
          <p className="text-sm text-destructive">{fieldErrors.password.join(' ')}</p>
        ) : null}
      </div>

      <Button type="submit" className="w-full" disabled={pending}>
        {pending ? <Loader2 aria-hidden="true" className="size-4 animate-spin" /> : null}
        Create account
      </Button>

      <p className="text-center text-sm text-muted-foreground">
        Already have an account?{' '}
        <Link href="/login" className="text-foreground underline underline-offset-4">
          Sign in
        </Link>
      </p>
    </form>
  );
}
