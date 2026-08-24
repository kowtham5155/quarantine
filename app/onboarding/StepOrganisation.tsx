'use client';

import { useActionState, useState } from 'react';
import { Loader2 } from 'lucide-react';

import { createOrgAction } from '@/app/onboarding/actions';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { initialFormState } from '@/lib/form-state';

/** Mirrors the server's `slugify`, purely so the preview is not a surprise. */
function previewSlug(name: string): string {
  const base = name
    .normalize('NFKD')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
  return base.length >= 3 ? base : '';
}

export function StepOrganisation() {
  const [state, formAction, pending] = useActionState(createOrgAction, initialFormState);
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');

  const fieldErrors = state.fieldErrors ?? {};
  const effectiveSlug = slug || previewSlug(name);

  return (
    <form action={formAction} className="space-y-5" noValidate>
      {state.status === 'error' && state.message ? (
        <Alert variant="destructive" role="alert">
          <AlertTitle>Could not create the organisation</AlertTitle>
          <AlertDescription>{state.message}</AlertDescription>
        </Alert>
      ) : null}

      <div className="space-y-2">
        <Label htmlFor="name">Organisation name</Label>
        <Input
          id="name"
          name="name"
          required
          autoFocus
          maxLength={80}
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder="Acme Corp"
          aria-invalid={Boolean(fieldErrors.name)}
          aria-describedby={fieldErrors.name ? 'org-name-error' : undefined}
        />
        {fieldErrors.name ? (
          <p id="org-name-error" className="text-sm text-destructive">
            {fieldErrors.name.join(' ')}
          </p>
        ) : null}
      </div>

      <div className="space-y-2">
        <Label htmlFor="slug">
          URL <span className="font-normal text-muted-foreground">(optional)</span>
        </Label>
        <Input
          id="slug"
          name="slug"
          maxLength={48}
          value={slug}
          onChange={(event) => setSlug(event.target.value)}
          placeholder={previewSlug(name) || 'acme-corp'}
          className="font-mono"
          aria-invalid={Boolean(fieldErrors.slug)}
          aria-describedby="slug-help"
        />
        <p id="slug-help" className="text-sm text-muted-foreground">
          {effectiveSlug ? (
            <>
              Your workspace will live at{' '}
              <span className="font-mono text-foreground">quarantine.dev/{effectiveSlug}</span>
            </>
          ) : (
            'Lowercase letters, numbers and single hyphens. We will pick one if you leave this blank.'
          )}
        </p>
        {fieldErrors.slug ? (
          <p className="text-sm text-destructive">{fieldErrors.slug.join(' ')}</p>
        ) : null}
      </div>

      <Button type="submit" disabled={pending}>
        {pending ? <Loader2 aria-hidden="true" className="size-4 animate-spin" /> : null}
        Create organisation
      </Button>
    </form>
  );
}
