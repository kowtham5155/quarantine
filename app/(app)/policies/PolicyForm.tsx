'use client';

import { useActionState, useState } from 'react';
import Link from 'next/link';
import { FlaskConical, Loader2, Trash2 } from 'lucide-react';

import { ConfirmDialog } from '@/components/shared/ConfirmDialog';
import { EmptyState } from '@/components/shared/EmptyState';
import { FieldError, FormBanner } from '@/components/shared/FormFeedback';
import { PackageRef } from '@/components/shared/PackageRef';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { ecosystemSlug, versionHref } from '@/lib/routes';
import type { PolicyCondition } from '@/lib/policy-conditions';
import type { PolicySummary } from '@/lib/services/policy.service';

import { ConditionBuilder, type RuleOption } from './ConditionBuilder';
import {
  createPolicyAction,
  deletePolicyAction,
  previewPolicyAction,
  updatePolicyAction,
} from './actions';
import { initialPolicyState, initialPreviewState } from './policy-state';

export interface PolicyFormProps {
  /** Absent when creating. */
  policy?: PolicySummary;
  rules: readonly RuleOption[];
  canDelete?: boolean;
}

const ACTION_HELP = {
  BLOCK: 'Holds the package in quarantine and fails the check that asked about it.',
  WARN: 'Records a violation and lets the install proceed.',
  ALLOW: 'Explicitly clears anything matching, ahead of lower-priority policies.',
} as const;

/**
 * The policy editor, used for both creating and editing.
 *
 * The preview runs the conditions currently in the builder — not the saved
 * ones — against analyses the org has already completed, so "what would this
 * have blocked" is answerable before the policy is ever enabled.
 */
export function PolicyForm({ policy, rules, canDelete = false }: PolicyFormProps) {
  const editing = policy !== undefined;

  const [conditions, setConditions] = useState<PolicyCondition[]>(
    () => policy?.conditions ?? [{ type: 'verdict_at_least', verdict: 'SUSPICIOUS' }],
  );
  const [action, setAction] = useState<'ALLOW' | 'WARN' | 'BLOCK'>(policy?.action ?? 'BLOCK');
  const [enabled, setEnabled] = useState(policy?.enabled ?? true);
  const [confirming, setConfirming] = useState(false);

  const [saveState, saveAction, saving] = useActionState(
    editing ? updatePolicyAction : createPolicyAction,
    initialPolicyState,
  );
  const [previewState, runPreview, previewing] = useActionState(
    previewPolicyAction,
    initialPreviewState,
  );
  const [deleteState, deleteAction, deleting] = useActionState(
    deletePolicyAction,
    initialPolicyState,
  );

  const preview = previewState.preview;

  return (
    <div className="space-y-6">
      <form action={saveAction} className="space-y-6" id="policy-form">
        {editing ? <input type="hidden" name="policyId" value={policy.id} /> : null}
        <input type="hidden" name="action" value={action} />
        <input type="hidden" name="enabled" value={enabled ? 'true' : 'false'} />

        <FormBanner state={saveState} />

        <Card>
          <CardHeader>
            <CardTitle className="text-base">What this policy is</CardTitle>
            <CardDescription>
              Policies are evaluated in priority order, lowest number first. The first one that
              matches decides the outcome.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                name="name"
                required
                maxLength={80}
                autoComplete="off"
                defaultValue={policy?.name ?? ''}
                placeholder="Block anything likely malicious"
              />
              <FieldError state={saveState} field="name" />
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
                defaultValue={policy?.description ?? ''}
                placeholder="Why this exists, and who to talk to about an exception."
              />
              <FieldError state={saveState} field="description" />
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="policy-action">Action</Label>
                <Select
                  value={action}
                  onValueChange={(value) => setAction(value as 'ALLOW' | 'WARN' | 'BLOCK')}
                >
                  <SelectTrigger id="policy-action" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="BLOCK">Block</SelectItem>
                    <SelectItem value="WARN">Warn</SelectItem>
                    <SelectItem value="ALLOW">Allow</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">{ACTION_HELP[action]}</p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="priority">Priority</Label>
                <Input
                  id="priority"
                  name="priority"
                  type="number"
                  min={1}
                  max={1000}
                  defaultValue={policy?.priority ?? 100}
                  className="w-32"
                />
                <p className="text-xs text-muted-foreground">
                  Lower runs first. Put an ALLOW exception above the BLOCK it carves out of.
                </p>
                <FieldError state={saveState} field="priority" />
              </div>
            </div>

            <div className="flex items-center gap-3">
              <Switch id="enabled" checked={enabled} onCheckedChange={setEnabled} />
              <Label htmlFor="enabled" className="font-normal">
                Enforcing
                <span className="text-muted-foreground">
                  {enabled ? '— evaluated on every analysis' : '— saved, but never evaluated'}
                </span>
              </Label>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">When it fires</CardTitle>
            <CardDescription>
              A policy sees one analysed package version at a time. Anything it cannot know —
              a package the engine has never looked at — matches nothing.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <ConditionBuilder conditions={conditions} onChange={setConditions} rules={rules} />
            <FieldError state={saveState} field="conditions" />
          </CardContent>
        </Card>

        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={saving || conditions.length === 0}>
            {saving ? <Loader2 aria-hidden="true" className="animate-spin" /> : null}
            {saving ? 'Saving…' : editing ? 'Save policy' : 'Create policy'}
          </Button>
          <Button asChild variant="ghost">
            <Link href="/policies">Cancel</Link>
          </Button>
        </div>
      </form>

      {/* Its own form: the preview must not submit the editor, and it posts the
          conditions as they stand rather than as they were last saved. */}
      <form action={runPreview}>
        <input type="hidden" name="conditions" value={JSON.stringify(conditions)} />
        <input type="hidden" name="action" value={action} />

        <Card>
          <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="space-y-1.5">
              <CardTitle className="text-base">What this would have caught</CardTitle>
              <CardDescription>
                Runs these conditions over analyses this organisation has already completed. Nothing
                is written: no violation, no quarantine, no notification.
              </CardDescription>
            </div>
            <Button type="submit" variant="outline" disabled={previewing || conditions.length === 0}>
              {previewing ? (
                <Loader2 aria-hidden="true" className="animate-spin" />
              ) : (
                <FlaskConical aria-hidden="true" />
              )}
              {previewing ? 'Evaluating…' : 'Run preview'}
            </Button>
          </CardHeader>
          <CardContent className="space-y-4">
            <FormBanner state={previewState} />

            {preview ? (
              preview.matched === 0 ? (
                <EmptyState
                  size="sm"
                  icon={FlaskConical}
                  title="Nothing in the window matches"
                  description={`Checked the last ${preview.evaluated.toLocaleString('en-GB')} completed analyses. That is not proof the policy is wrong — it may simply be about something this organisation has not met yet.`}
                />
              ) : (
                <div className="space-y-4">
                  <div className="flex flex-wrap items-center gap-3 text-sm">
                    <Badge
                      variant={preview.action === 'BLOCK' ? 'destructive' : 'secondary'}
                      className="font-mono text-[11px]"
                    >
                      would {preview.action.toLowerCase()}
                    </Badge>
                    <span className="font-mono tabular-nums">
                      {preview.matched.toLocaleString('en-GB')}
                    </span>
                    <span className="text-muted-foreground">
                      of {preview.evaluated.toLocaleString('en-GB')} analyses in the window
                      {preview.truncated ? ` (the most recent ${preview.windowSize})` : ''}
                    </span>
                  </div>

                  <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border">
                    {preview.samples.map((sample) => (
                      <li
                        key={sample.analysisId}
                        className="flex flex-wrap items-center gap-2 px-3 py-2"
                      >
                        <PackageRef
                          name={sample.name}
                          version={sample.version}
                          ecosystem={ecosystemSlug(sample.ecosystem)}
                          href={versionHref(sample.ecosystem, sample.name, sample.version)}
                          size="sm"
                        />
                        <span className="ml-auto">
                          {sample.verdict ? (
                            <VerdictBadge verdict={sample.verdict} size="sm" />
                          ) : null}
                        </span>
                      </li>
                    ))}
                  </ul>

                  {preview.matched > preview.samples.length ? (
                    <p className="text-xs text-muted-foreground">
                      Showing {preview.samples.length} of {preview.matched.toLocaleString('en-GB')}{' '}
                      matches.
                    </p>
                  ) : null}
                </div>
              )
            ) : (
              <p className="text-sm text-muted-foreground">
                Run the preview before enabling a BLOCK policy. It is the difference between
                knowing what this stops and finding out during a release.
              </p>
            )}
          </CardContent>
        </Card>
      </form>

      {editing && canDelete ? (
        <Card className="border-verdict-likely-malicious-accent/40">
          <CardHeader>
            <CardTitle className="text-base">Delete this policy</CardTitle>
            <CardDescription>
              Violations already raised by it are kept — they are a record of what was decided at
              the time. Nothing new will be raised.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <FormBanner state={deleteState} />

            <form action={deleteAction} id="delete-policy">
              <input type="hidden" name="policyId" value={policy.id} />
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
                {deleting ? 'Deleting…' : 'Delete policy'}
              </Button>
            </form>

            <ConfirmDialog
              open={confirming}
              onOpenChange={setConfirming}
              title="Delete this policy?"
              description="Packages it currently holds stay in quarantine until they are reviewed. Disable it instead if you only want to stop enforcing for now."
              confirmLabel="Delete policy"
              destructive
              onConfirm={() => {
                setConfirming(false);
                (
                  document.getElementById('delete-policy') as HTMLFormElement | null
                )?.requestSubmit();
              }}
            />
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
