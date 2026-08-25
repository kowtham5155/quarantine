'use client';

import { useActionState } from 'react';
import Link from 'next/link';
import { ArrowRight, Loader2, MailCheck } from 'lucide-react';

import { inviteTeamAction } from '@/app/onboarding/actions';
import { initialInviteState } from '@/app/onboarding/form-states';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

const ROLE_OPTIONS = [
  { value: 'VIEWER', label: 'Viewer', hint: 'Read-only access to verdicts and reports' },
  { value: 'ANALYST', label: 'Analyst', hint: 'Runs scans, triages violations' },
  { value: 'ADMIN', label: 'Admin', hint: 'Manages policy, members and integrations' },
] as const;

export function StepTeam({ maxRole }: { maxRole: string }) {
  const [state, formAction, pending] = useActionState(inviteTeamAction, initialInviteState);

  const allowed = ROLE_OPTIONS.filter((option) =>
    maxRole === 'OWNER' || maxRole === 'ADMIN' ? true : option.value === 'VIEWER',
  );

  const sent = state.sent ?? [];
  const links = state.links ?? {};

  return (
    <div className="space-y-6">
      <form action={formAction} className="space-y-4" noValidate>
        {state.status === 'error' && state.message ? (
          <Alert variant="destructive" role="alert">
            <AlertTitle>Could not send the invitation</AlertTitle>
            <AlertDescription>{state.message}</AlertDescription>
          </Alert>
        ) : null}

        {state.status === 'success' && state.message ? (
          <Alert>
            <MailCheck aria-hidden="true" className="size-4" />
            <AlertTitle>{state.message}</AlertTitle>
          </Alert>
        ) : null}

        <div className="grid gap-4 sm:grid-cols-[1fr_auto]">
          <div className="space-y-2">
            <Label htmlFor="invite-email">Email</Label>
            <Input
              id="invite-email"
              name="email"
              type="email"
              inputMode="email"
              placeholder="teammate@example.com"
              required
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="invite-role">Role</Label>
            <Select name="role" defaultValue="ANALYST">
              <SelectTrigger id="invite-role" className="w-full sm:w-44">
                <SelectValue placeholder="Choose a role" />
              </SelectTrigger>
              <SelectContent>
                {allowed.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <ul className="space-y-1 text-sm text-muted-foreground">
          {allowed.map((option) => (
            <li key={option.value}>
              <span className="font-medium text-foreground">{option.label}</span> — {option.hint}
            </li>
          ))}
        </ul>

        <Button type="submit" variant="outline" disabled={pending}>
          {pending ? <Loader2 aria-hidden="true" className="size-4 animate-spin" /> : null}
          Send invitation
        </Button>
      </form>

      {sent.length > 0 ? (
        <div className="space-y-2 rounded-md border border-border p-3">
          <p className="text-sm font-medium">Invited</p>
          <ul className="space-y-2">
            {sent.map((email) => {
              const link = links[email];
              return (
                <li key={email} className="flex flex-wrap items-center gap-2 text-sm">
                  <Badge variant="secondary" className="font-mono text-xs">
                    {email}
                  </Badge>
                  {link ? (
                    <Link
                      href={link}
                      className="font-mono text-xs break-all text-primary underline underline-offset-4"
                    >
                      {link}
                    </Link>
                  ) : null}
                </li>
              );
            })}
          </ul>
        </div>
      ) : null}

      <div className="flex flex-wrap gap-2">
        <Button asChild>
          <Link href="/onboarding?step=3">
            Continue
            <ArrowRight aria-hidden="true" className="size-4" />
          </Link>
        </Button>
        <Button asChild variant="ghost">
          <Link href="/onboarding?step=3">Skip for now</Link>
        </Button>
      </div>
    </div>
  );
}
