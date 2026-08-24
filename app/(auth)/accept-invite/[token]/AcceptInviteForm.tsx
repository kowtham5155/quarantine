'use client';

import { useActionState } from 'react';
import { Loader2 } from 'lucide-react';

import { acceptInviteAction } from '@/app/(auth)/actions';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { initialFormState } from '@/lib/form-state';

export function AcceptInviteForm({ token, orgName }: { token: string; orgName: string }) {
  const [state, formAction, pending] = useActionState(acceptInviteAction, initialFormState);

  return (
    <form action={formAction} className="space-y-4">
      <input type="hidden" name="token" value={token} />

      {state.status === 'error' && state.message ? (
        <Alert variant="destructive" role="alert">
          <AlertTitle>Could not accept the invitation</AlertTitle>
          <AlertDescription>{state.message}</AlertDescription>
        </Alert>
      ) : null}

      <Button type="submit" className="w-full" disabled={pending}>
        {pending ? <Loader2 aria-hidden="true" className="size-4 animate-spin" /> : null}
        Join {orgName}
      </Button>
    </form>
  );
}
