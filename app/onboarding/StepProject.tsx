'use client';

import { useActionState } from 'react';
import { Loader2 } from 'lucide-react';

import { createProjectAction } from '@/app/onboarding/actions';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
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
import { Textarea } from '@/components/ui/textarea';
import { initialFormState } from '@/lib/form-state';

const ECOSYSTEMS = [
  { value: 'NPM', label: 'npm' },
  { value: 'PYPI', label: 'PyPI' },
] as const;

export function StepProject() {
  const [state, formAction, pending] = useActionState(createProjectAction, initialFormState);
  const fieldErrors = state.fieldErrors ?? {};

  return (
    <form action={formAction} className="space-y-5" noValidate>
      {state.status === 'error' && state.message ? (
        <Alert variant="destructive" role="alert">
          <AlertTitle>Could not create the project</AlertTitle>
          <AlertDescription>{state.message}</AlertDescription>
        </Alert>
      ) : null}

      <div className="space-y-2">
        <Label htmlFor="project-name">Project name</Label>
        <Input
          id="project-name"
          name="name"
          required
          autoFocus
          maxLength={80}
          placeholder="payments-api"
          className="font-mono"
          aria-invalid={Boolean(fieldErrors.name)}
          aria-describedby={fieldErrors.name ? 'project-name-error' : undefined}
        />
        {fieldErrors.name ? (
          <p id="project-name-error" className="text-sm text-destructive">
            {fieldErrors.name.join(' ')}
          </p>
        ) : null}
      </div>

      <div className="space-y-2">
        <Label htmlFor="ecosystem">Ecosystem</Label>
        <Select name="ecosystem" defaultValue="NPM">
          <SelectTrigger id="ecosystem" className="w-full sm:w-56">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ECOSYSTEMS.map((option) => (
              <SelectItem key={option.value} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2">
        <Label htmlFor="repoUrl">
          Repository URL <span className="font-normal text-muted-foreground">(optional)</span>
        </Label>
        <Input
          id="repoUrl"
          name="repoUrl"
          type="url"
          inputMode="url"
          placeholder="https://github.com/acme/payments-api"
          className="font-mono"
          aria-invalid={Boolean(fieldErrors.repoUrl)}
          aria-describedby="repo-help"
        />
        <p id="repo-help" className="text-sm text-muted-foreground">
          A public repository lets us compare the published tarball against the source tree.
        </p>
        {fieldErrors.repoUrl ? (
          <p className="text-sm text-destructive">{fieldErrors.repoUrl.join(' ')}</p>
        ) : null}
      </div>

      <div className="space-y-2">
        <Label htmlFor="description">
          Description <span className="font-normal text-muted-foreground">(optional)</span>
        </Label>
        <Textarea id="description" name="description" maxLength={500} rows={3} />
      </div>

      <Button type="submit" disabled={pending}>
        {pending ? <Loader2 aria-hidden="true" className="size-4 animate-spin" /> : null}
        Create project and finish
      </Button>
    </form>
  );
}
