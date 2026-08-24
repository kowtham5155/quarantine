'use client';

import { useActionState, useState } from 'react';
import { Loader2 } from 'lucide-react';

import { resetPasswordAction } from '@/app/(auth)/actions';
import { PasswordStrength } from '@/app/(auth)/register/PasswordStrength';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { initialFormState } from '@/lib/form-state';

export function ResetPasswordForm({ token }: { token: string }) {
  const [state, formAction, pending] = useActionState(resetPasswordAction, initialFormState);
  const [password, setPassword] = useState('');

  const fieldErrors = state.fieldErrors ?? {};

  return (
    <form action={formAction} className="space-y-5" noValidate>
      <input type="hidden" name="token" value={token} />

      {state.status === 'error' && state.message ? (
        <Alert variant="destructive" role="alert">
          <AlertTitle>Could not reset the password</AlertTitle>
          <AlertDescription>{state.message}</AlertDescription>
        </Alert>
      ) : null}

      <div className="space-y-2">
        <Label htmlFor="password">New password</Label>
        <Input
          id="password"
          name="password"
          type="password"
          autoComplete="new-password"
          required
          autoFocus
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          aria-invalid={Boolean(fieldErrors.password)}
          aria-describedby="password-strength"
        />
        <div id="password-strength">
          <PasswordStrength password={password} userInputs={[]} />
        </div>
        {fieldErrors.password ? (
          <p className="text-sm text-destructive">{fieldErrors.password.join(' ')}</p>
        ) : null}
      </div>

      <p className="text-sm text-muted-foreground">
        Every other session for this account will be signed out.
      </p>

      <Button type="submit" className="w-full" disabled={pending}>
        {pending ? <Loader2 aria-hidden="true" className="size-4 animate-spin" /> : null}
        Set new password
      </Button>
    </form>
  );
}
