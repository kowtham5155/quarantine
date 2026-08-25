'use client';

import { useActionState, useState } from 'react';
import { FileUp, Loader2, PackageSearch } from 'lucide-react';

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
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

import { queueLockfileScanAction, queuePackageScanAction } from './actions';
import { initialScanState, type ScanFormState } from './scan-state';
import { ScanRunner } from './ScanRunner';

function FormError({ state, field }: { state: ScanFormState; field: string }) {
  const errors = state.fieldErrors?.[field];
  if (!errors || errors.length === 0) return null;
  return (
    <p id={`${field}-error`} className="text-sm text-verdict-suspicious-accent">
      {errors[0]}
    </p>
  );
}

function Banner({ state }: { state: ScanFormState }) {
  if (state.status !== 'error' || !state.message) return null;
  return (
    <p
      role="alert"
      className="rounded-md border border-verdict-suspicious-accent/40 bg-verdict-suspicious-surface px-3 py-2 text-sm text-verdict-suspicious-accent"
    >
      {state.message}
    </p>
  );
}

/**
 * The scan entry point.
 *
 * The action only queues; the analysis itself is streamed by ScanRunner from the
 * NDJSON run endpoint, which is why the queued list is kept in the form state
 * rather than redirecting straight to a report that does not exist yet.
 */
export function ScanForm() {
  const [packageState, packageAction, packagePending] = useActionState(
    queuePackageScanAction,
    initialScanState,
  );
  const [lockfileState, lockfileAction, lockfilePending] = useActionState(
    queueLockfileScanAction,
    initialScanState,
  );
  const [tab, setTab] = useState('package');

  const active = tab === 'package' ? packageState : lockfileState;

  return (
    <div className="space-y-6">
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="package">
            <PackageSearch aria-hidden="true" className="size-4" />
            Package
          </TabsTrigger>
          <TabsTrigger value="lockfile">
            <FileUp aria-hidden="true" className="size-4" />
            Lockfile
          </TabsTrigger>
        </TabsList>

        <TabsContent value="package" className="mt-4">
          <form action={packageAction} className="space-y-4">
            <Banner state={packageState} />

            <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
              <div className="sm:w-40">
                <Label htmlFor="ecosystem">Registry</Label>
                <Select name="ecosystem" defaultValue="NPM">
                  <SelectTrigger id="ecosystem" className="mt-1.5 w-full">
                    <SelectValue placeholder="Registry" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="NPM">npm</SelectItem>
                    <SelectItem value="PYPI">PyPI</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="min-w-0 flex-1">
                <Label htmlFor="coordinate">Package</Label>
                <Input
                  id="coordinate"
                  name="coordinate"
                  required
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="lodash@4.17.21 or @scope/name"
                  className="mt-1.5 font-mono"
                  aria-describedby={
                    packageState.fieldErrors?.coordinate ? 'coordinate-error' : 'coordinate-hint'
                  }
                />
              </div>

              <Button type="submit" disabled={packagePending} className="sm:w-32">
                {packagePending ? (
                  <>
                    <Loader2 aria-hidden="true" className="animate-spin" />
                    Queueing
                  </>
                ) : (
                  'Scan'
                )}
              </Button>
            </div>

            <FormError state={packageState} field="coordinate" />
            <FormError state={packageState} field="name" />
            <FormError state={packageState} field="version" />

            <p id="coordinate-hint" className="text-xs text-muted-foreground">
              Omit the version and the registry&apos;s current release is analysed. npm dist-tags
              are resolved to a concrete version before anything is downloaded.
            </p>
          </form>
        </TabsContent>

        <TabsContent value="lockfile" className="mt-4">
          <form action={lockfileAction} className="space-y-4">
            <Banner state={lockfileState} />

            <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
              <div className="min-w-0 flex-1">
                <Label htmlFor="lockfile">Lockfile</Label>
                <Input
                  id="lockfile"
                  name="lockfile"
                  type="file"
                  required
                  accept=".json,.lock,application/json,text/plain"
                  className="mt-1.5"
                  aria-describedby={
                    lockfileState.fieldErrors?.lockfile ? 'lockfile-error' : 'lockfile-hint'
                  }
                />
              </div>

              <Button type="submit" disabled={lockfilePending} className="sm:w-32">
                {lockfilePending ? (
                  <>
                    <Loader2 aria-hidden="true" className="animate-spin" />
                    Reading
                  </>
                ) : (
                  'Scan all'
                )}
              </Button>
            </div>

            <FormError state={lockfileState} field="lockfile" />

            <p id="lockfile-hint" className="text-xs text-muted-foreground">
              <code className="font-mono">package-lock.json</code> or{' '}
              <code className="font-mono">yarn.lock</code>, up to 8MB. The file is parsed in memory
              and never written to disk; the first 25 coordinates are queued.
            </p>
          </form>
        </TabsContent>
      </Tabs>

      {active.status === 'success' && active.queued.length > 0 ? (
        <section aria-label="Scan progress" className="space-y-4">
          {active.lockfile ? (
            <p className="text-sm text-muted-foreground">
              Read {active.lockfile.found} coordinates from that {active.lockfile.kind} file. Queued{' '}
              {active.lockfile.queued}
              {active.lockfile.skipped > 0 ? `, skipped ${active.lockfile.skipped}` : ''}
              {active.lockfile.truncated ? ' — the rest were beyond the 25-package upload cap' : ''}
              .
            </p>
          ) : null}

          <ScanRunner
            key={active.queued.map((scan) => scan.analysisId).join(',')}
            scans={active.queued}
          />
        </section>
      ) : null}
    </div>
  );
}
