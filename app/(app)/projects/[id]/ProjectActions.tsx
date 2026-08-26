'use client';

import { useActionState } from 'react';
import { FileUp, Loader2, Radar } from 'lucide-react';

import { FormBanner } from '@/components/shared/FormFeedback';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

import { importLockfileAction, scanDependenciesAction } from '../actions';
import { initialProjectState } from '../project-state';

export interface ProjectActionsProps {
  projectId: string;
  /** How many dependencies have no verdict yet. */
  unanalysed: number;
  queueLimit: number;
  canImport: boolean;
  canScan: boolean;
}

/**
 * The two things you do to a project graph: replace it from a lockfile, and
 * queue analyses for the packages in it that have never been looked at.
 *
 * Both are bounded server-side. Scanning takes the first `queueLimit`
 * coordinates and reports what is left rather than pretending the graph is
 * covered; the lockfile is parsed as text and nothing in it is installed or
 * executed (THE SAFETY RULE).
 */
export function ProjectActions({
  projectId,
  unanalysed,
  queueLimit,
  canImport,
  canScan,
}: ProjectActionsProps) {
  const [importState, importAction, importing] = useActionState(
    importLockfileAction,
    initialProjectState,
  );
  const [scanState, scanAction, scanning] = useActionState(
    scanDependenciesAction,
    initialProjectState,
  );

  if (!canImport && !canScan) return null;

  return (
    <div className="space-y-3 rounded-lg border border-border bg-surface/40 p-4">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        {canImport ? (
          <form action={importAction} className="min-w-0 space-y-2">
            <input type="hidden" name="projectId" value={projectId} />
            <Label htmlFor="lockfile" className="text-sm">
              Replace the graph
            </Label>
            <div className="flex flex-wrap items-center gap-2">
              <Input
                id="lockfile"
                name="lockfile"
                type="file"
                accept=".json,.lock,application/json,text/plain"
                className="w-full sm:w-72"
                aria-describedby="lockfile-help"
              />
              <Button type="submit" variant="outline" disabled={importing}>
                {importing ? (
                  <Loader2 aria-hidden="true" className="animate-spin" />
                ) : (
                  <FileUp aria-hidden="true" />
                )}
                {importing ? 'Reading…' : 'Import lockfile'}
              </Button>
            </div>
            <p id="lockfile-help" className="text-xs text-muted-foreground">
              A lockfile states the whole graph, so an import replaces it. Nothing is installed.
            </p>
          </form>
        ) : null}

        {canScan ? (
          <form action={scanAction} className="shrink-0 space-y-2">
            <input type="hidden" name="projectId" value={projectId} />
            <Button type="submit" disabled={scanning || unanalysed === 0}>
              {scanning ? (
                <Loader2 aria-hidden="true" className="animate-spin" />
              ) : (
                <Radar aria-hidden="true" />
              )}
              {scanning ? 'Queueing…' : 'Scan dependencies'}
            </Button>
            <p className="text-xs text-muted-foreground">
              {unanalysed === 0
                ? 'Every dependency has a verdict.'
                : `${unanalysed.toLocaleString('en-GB')} without a verdict · ${queueLimit} queued per run.`}
            </p>
          </form>
        ) : null}
      </div>

      <FormBanner state={importState} />
      <FormBanner state={scanState} />
    </div>
  );
}
