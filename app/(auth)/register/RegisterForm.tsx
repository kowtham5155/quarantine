'use client';

import { useActionState, useState } from 'react';
import Link from 'next/link';
import { CircleCheck, Loader2 } from 'lucide-react';

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
          <CircleCheck aria-hidden="true" className="size-4" />
          <AlertTitle>Your account is ready</AlertTitle>
          <AlertDescription>
            {/* There is no email verification step and no mail transport in this
                deployment, so there is nothing to send and nothing to wait for.
                Say that plainly rather than pointing at an empty inbox. */}
            If that address could be registered,{' '}
            <span className="font-mono">{state.registeredEmail}</span> can sign in now. There is no
            confirmation email to wait for.
          </AlertDescription>
        </Alert>

        <Button asChild className="w-full">
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
