'use client';

import { useActionState, useState } from 'react';
import { Loader2, Trash2 } from 'lucide-react';

import { ConfirmDialog } from '@/components/shared/ConfirmDialog';
import { FieldError, FormBanner } from '@/components/shared/FormFeedback';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import type { ProjectSummary } from '@/lib/services/project.service';

import { deleteProjectAction, updateProjectAction } from '../../actions';
import { initialProjectState } from '../../project-state';

export interface ProjectSettingsFormProps {
  project: ProjectSummary;
  canEdit: boolean;
  canDelete: boolean;
}

export function ProjectSettingsForm({ project, canEdit, canDelete }: ProjectSettingsFormProps) {
  const [state, action, pending] = useActionState(updateProjectAction, initialProjectState);
  const [deleteState, deleteAction, deleting] = useActionState(
    deleteProjectAction,
    initialProjectState,
  );
  const [confirming, setConfirming] = useState(false);

  return (
    <div className="space-y-6">
      <form action={action}>
        <input type="hidden" name="projectId" value={project.id} />

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Project details</CardTitle>
            <CardDescription>
              The registry a project reads against is fixed at creation: changing it would leave a
              graph of npm coordinates being resolved against PyPI.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <FormBanner state={state} />

            <div className="space-y-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                name="name"
                required
                maxLength={80}
                defaultValue={project.name}
                disabled={!canEdit}
                autoComplete="off"
              />
              <FieldError state={state} field="name" />
            </div>

            <div className="space-y-2">
              <Label htmlFor="description">
                Description <span className="text-muted-foreground">(optional)</span>
              </Label>
              <Textarea
                id="description"
                name="description"
                rows={2}
                maxLength={500}
                defaultValue={project.description ?? ''}
                disabled={!canEdit}
              />
              <FieldError state={state} field="description" />
            </div>

            <div className="space-y-2">
              <Label htmlFor="repoUrl">
                Repository URL <span className="text-muted-foreground">(optional)</span>
              </Label>
              <Input
                id="repoUrl"
                name="repoUrl"
                type="url"
                maxLength={500}
                defaultValue={project.repoUrl ?? ''}
                disabled={!canEdit}
                placeholder="https://github.com/acme/checkout-api"
              />
              <FieldError state={state} field="repoUrl" />
              <p className="text-xs text-muted-foreground">
                Recorded and linked, never cloned. The graph comes from the lockfile you upload.
              </p>
            </div>

            {canEdit ? (
              <Button type="submit" disabled={pending}>
                {pending ? <Loader2 aria-hidden="true" className="animate-spin" /> : null}
                {pending ? 'Saving…' : 'Save changes'}
              </Button>
            ) : (
              <p className="text-sm text-muted-foreground">
                Your role can read this project but not change it.
              </p>
            )}
          </CardContent>
        </Card>
      </form>

      {canDelete ? (
        <Card className="border-verdict-likely-malicious-accent/40">
          <CardHeader>
            <CardTitle className="text-base">Delete this project</CardTitle>
            <CardDescription>
              Removes the project, its dependency graph and its import history. Analyses of the
              packages themselves are org-wide and are kept — deleting a project must not erase
              evidence that another project still depends on.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <FormBanner state={deleteState} />

            {/* The dialog gates the click; the deletion itself is a Server Action
                form submit, so it works the same with JavaScript unavailable. */}
            <form action={deleteAction} id="delete-project">
              <input type="hidden" name="projectId" value={project.id} />
              <Button
                type="submit"
                variant="destructive"
                disabled={deleting}
                onClick={(event) => {
                  if (confirming) return;
                  event.preventDefault();
                  setConfirming(true);
                }}
              >
                {deleting ? (
                  <Loader2 aria-hidden="true" className="animate-spin" />
                ) : (
                  <Trash2 aria-hidden="true" />
                )}
                {deleting ? 'Deleting…' : 'Delete project'}
              </Button>
            </form>

            <ConfirmDialog
              open={confirming}
              onOpenChange={setConfirming}
              title="Delete this project?"
              description={
                <>
                  The dependency graph and every import recorded against{' '}
                  <span className="font-mono">{project.name}</span> go with it. This cannot be
                  undone.
                </>
              }
              confirmLabel="Delete project"
              destructive
              requireTypedConfirmation={project.name}
              onConfirm={() => {
                setConfirming(false);
                (
                  document.getElementById('delete-project') as HTMLFormElement | null
                )?.requestSubmit();
              }}
            />
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
