'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { AlertTriangle, Check, CircleDashed, Loader2, MinusCircle } from 'lucide-react';

import { ConfidenceMeter } from '@/components/shared/ConfidenceMeter';
import { PackageRef } from '@/components/shared/PackageRef';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { isVerdict, SIGNAL_FAMILIES, SIGNAL_FAMILY_META, type Verdict } from '@/lib/constants';
import { ecosystemSlug, versionHref } from '@/lib/routes';
import { cn } from '@/lib/utils';

import type { QueuedScan } from './scan-state';

type StageStatus = 'pending' | 'started' | 'completed' | 'failed' | 'skipped';

interface StageState {
  status: StageStatus;
  detail?: string;
  elapsedMs?: number;
}

interface ScanResult {
  verdict: Verdict;
  confidence: number;
  weightedScore: number;
  partial: boolean;
  durationMs: number;
  firedSignals: number;
  evaluatedSignals: number;
  hardTriggers: Array<{ id: string; label: string }>;
}

interface ScanState {
  phase: 'pending' | 'running' | 'done' | 'failed';
  stages: Record<string, StageState>;
  result: ScanResult | null;
  error: string | null;
}

const PIPELINE_STAGES: Array<{ id: string; label: string }> = [
  { id: 'metadata', label: 'Registry metadata' },
  { id: 'download', label: 'Download tarball' },
  { id: 'extract', label: 'Bounded extraction' },
  { id: 'repository', label: 'Repository snapshot' },
];

const FAMILY_STAGES = SIGNAL_FAMILIES.map((family) => ({
  id: family,
  label: SIGNAL_FAMILY_META[family].label,
}));

function emptyState(): ScanState {
  return { phase: 'pending', stages: {}, result: null, error: null };
}

function StageIcon({ status }: { status: StageStatus }) {
  if (status === 'completed') {
    return <Check aria-hidden="true" className="size-4 text-verdict-clean-accent" />;
  }
  if (status === 'started') {
    return <Loader2 aria-hidden="true" className="size-4 animate-spin text-primary" />;
  }
  if (status === 'failed') {
    return <AlertTriangle aria-hidden="true" className="size-4 text-verdict-suspicious-accent" />;
  }
  if (status === 'skipped') {
    return <MinusCircle aria-hidden="true" className="size-4 text-muted-foreground" />;
  }
  return <CircleDashed aria-hidden="true" className="size-4 text-muted-foreground/60" />;
}

function StageRow({ label, state }: { label: string; state: StageState | undefined }) {
  const status = state?.status ?? 'pending';
  return (
    <li className="flex items-center gap-2.5 py-1.5">
      <StageIcon status={status} />
      <span
        className={cn(
          'text-sm',
          status === 'pending' ? 'text-muted-foreground/70' : 'text-foreground',
        )}
      >
        {label}
      </span>
      {state?.detail ? (
        <span className="break-anywhere min-w-0 truncate text-xs text-muted-foreground">
          {state.detail}
        </span>
      ) : null}
      {typeof state?.elapsedMs === 'number' && status !== 'started' ? (
        <span className="ml-auto shrink-0 font-mono text-xs text-muted-foreground tabular-nums">
          {(state.elapsedMs / 1000).toFixed(1)}s
        </span>
      ) : null}
    </li>
  );
}

export interface ScanRunnerProps {
  scans: QueuedScan[];
  /** Navigate to the report when a single scan finishes. */
  navigateOnComplete?: boolean;
}

/**
 * Runs queued analyses and renders their progress.
 *
 * The run endpoint streams NDJSON — one JSON object per line — so this reads the
 * body incrementally rather than awaiting a whole response. Scans run one at a
 * time: each is a tarball download plus six analysis families, and firing
 * twenty-five of them at once would only queue them behind each other on the
 * server while making the page lie about what is happening.
 *
 * Every string in these events is package-derived. React escapes them on render
 * and nothing here interpolates them into markup.
 */
export function ScanRunner({ scans, navigateOnComplete = false }: ScanRunnerProps) {
  const router = useRouter();
  const [states, setStates] = useState<Record<string, ScanState>>(() =>
    Object.fromEntries(scans.map((scan) => [scan.analysisId, emptyState()])),
  );
  const startedRef = useRef(false);

  const update = useCallback((analysisId: string, patch: (previous: ScanState) => ScanState) => {
    setStates((previous) => ({
      ...previous,
      [analysisId]: patch(previous[analysisId] ?? emptyState()),
    }));
  }, []);

  useEffect(() => {
    if (startedRef.current || scans.length === 0) return;
    startedRef.current = true;

    const runOne = async (scan: QueuedScan): Promise<void> => {
      update(scan.analysisId, (previous) => ({ ...previous, phase: 'running' }));

      let response: Response;
      try {
        response = await fetch(`/api/analyses/${encodeURIComponent(scan.analysisId)}/run`, {
          method: 'POST',
          headers: { accept: 'application/x-ndjson' },
        });
      } catch {
        update(scan.analysisId, (previous) => ({
          ...previous,
          phase: 'failed',
          error: 'The scan could not be started. Check your connection and try again.',
        }));
        return;
      }

      if (!response.ok || !response.body) {
        // The route answers with a public error body whose message its author
        // marked safe to show. Replacing it with a generic line throws away the
        // only thing that explains the failure — an analysis already running, a
        // rejected origin, a row that belongs to another org — and leaves the
        // user with nothing to act on.
        let error = 'The scan could not be started.';

        if (response.status === 429) {
          error = 'Scan rate limit reached. Try again shortly.';
        } else {
          try {
            const body = (await response.json()) as { error?: { message?: unknown } };
            if (typeof body.error?.message === 'string' && body.error.message.length > 0) {
              error = body.error.message;
            }
          } catch {
            // Not our JSON — a proxy error page, say. Keep the generic line.
          }
        }

        update(scan.analysisId, (previous) => ({ ...previous, phase: 'failed', error }));
        return;
      }

      const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
      let buffer = '';

      const handleLine = (line: string): void => {
        if (line.trim().length === 0) return;

        let event: Record<string, unknown>;
        try {
          event = JSON.parse(line) as Record<string, unknown>;
        } catch {
          return;
        }

        if (event.event === 'progress' && typeof event.stage === 'string') {
          const stage = event.stage;
          const status =
            typeof event.status === 'string' ? (event.status as StageStatus) : 'started';
          const detail = typeof event.detail === 'string' ? event.detail : undefined;
          const elapsedMs = typeof event.elapsedMs === 'number' ? event.elapsedMs : undefined;

          update(scan.analysisId, (previous) => ({
            ...previous,
            stages: {
              ...previous.stages,
              [stage]: {
                status,
                ...(detail === undefined ? {} : { detail }),
                ...(elapsedMs === undefined ? {} : { elapsedMs }),
              },
            },
          }));
          return;
        }

        if (event.event === 'result' && isVerdict(event.verdict)) {
          const result: ScanResult = {
            verdict: event.verdict,
            confidence: typeof event.confidence === 'number' ? event.confidence : 0,
            weightedScore: typeof event.weightedScore === 'number' ? event.weightedScore : 0,
            partial: event.partial === true,
            durationMs: typeof event.durationMs === 'number' ? event.durationMs : 0,
            firedSignals: typeof event.firedSignals === 'number' ? event.firedSignals : 0,
            evaluatedSignals:
              typeof event.evaluatedSignals === 'number' ? event.evaluatedSignals : 0,
            hardTriggers: Array.isArray(event.hardTriggers)
              ? event.hardTriggers.flatMap((trigger) =>
                  trigger &&
                  typeof trigger === 'object' &&
                  typeof (trigger as { id?: unknown }).id === 'string' &&
                  typeof (trigger as { label?: unknown }).label === 'string'
                    ? [
                        {
                          id: String((trigger as { id: string }).id),
                          label: String((trigger as { label: string }).label),
                        },
                      ]
                    : [],
                )
              : [],
          };

          update(scan.analysisId, (previous) => ({ ...previous, phase: 'done', result }));
          return;
        }

        if (event.event === 'error') {
          const message =
            typeof event.message === 'string'
              ? event.message
              : 'The analysis could not be completed.';
          update(scan.analysisId, (previous) => ({ ...previous, phase: 'failed', error: message }));
        }
      };

      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += value;
          let newline = buffer.indexOf('\n');
          while (newline !== -1) {
            handleLine(buffer.slice(0, newline));
            buffer = buffer.slice(newline + 1);
            newline = buffer.indexOf('\n');
          }
        }
        if (buffer.length > 0) handleLine(buffer);
      } catch {
        update(scan.analysisId, (previous) =>
          previous.phase === 'done'
            ? previous
            : { ...previous, phase: 'failed', error: 'The scan stream ended unexpectedly.' },
        );
      } finally {
        reader.releaseLock();
      }
    };

    void (async () => {
      for (const scan of scans) {
        await runOne(scan);
      }

      if (navigateOnComplete && scans.length === 1) {
        const only = scans[0];
        if (only) {
          router.refresh();
          router.push(versionHref(only.ecosystem, only.name, only.version));
        }
      }
    })();

    // Deliberately no cleanup that stops the read loop.
    //
    // An effect cleanup runs on every remount — including the immediate
    // mount/unmount/mount React does in development — and cancelling there
    // killed the stream a few milliseconds after it opened while `startedRef`
    // stopped the remount from opening a new one. The result was a card that
    // sat on "Analysing" forever while the scan it was watching finished
    // server-side. The run is persisted by `runAnalysis` whoever is listening
    // (see the route handler's note on disconnects), so letting the reader
    // finish is both correct and cheap.
  }, [scans, update, navigateOnComplete, router]);

  return (
    <div className="space-y-4">
      {scans.map((scan) => {
        const state = states[scan.analysisId] ?? emptyState();
        const href = versionHref(scan.ecosystem, scan.name, scan.version);

        return (
          <Card key={scan.analysisId}>
            <CardHeader className="gap-2">
              <CardTitle className="flex flex-wrap items-center justify-between gap-3 text-base">
                <PackageRef
                  name={scan.name}
                  version={scan.version}
                  ecosystem={ecosystemSlug(scan.ecosystem)}
                />
                {state.result ? (
                  <VerdictBadge verdict={state.result.verdict} appearance="solid" />
                ) : state.phase === 'failed' ? (
                  <span className="text-xs font-medium text-verdict-suspicious-accent">Failed</span>
                ) : (
                  <span className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
                    <Loader2 aria-hidden="true" className="size-3.5 animate-spin" />
                    {state.phase === 'pending' ? 'Queued' : 'Analysing'}
                  </span>
                )}
              </CardTitle>
            </CardHeader>

            <CardContent className="space-y-4">
              {state.error ? (
                <p
                  role="alert"
                  className="rounded-md border border-verdict-suspicious-accent/40 bg-verdict-suspicious-surface px-3 py-2 text-sm text-verdict-suspicious-accent"
                >
                  {state.error}
                </p>
              ) : null}

              <div className="grid gap-x-8 gap-y-1 sm:grid-cols-2">
                <ul aria-label="Pipeline">
                  {PIPELINE_STAGES.map((stage) => (
                    <StageRow key={stage.id} label={stage.label} state={state.stages[stage.id]} />
                  ))}
                </ul>
                <ul aria-label="Signal families">
                  {FAMILY_STAGES.map((stage) => (
                    <StageRow key={stage.id} label={stage.label} state={state.stages[stage.id]} />
                  ))}
                </ul>
              </div>

              {state.result ? (
                <div className="space-y-3 rounded-lg border border-border bg-surface/50 p-4">
                  <div className="grid gap-3 sm:grid-cols-3">
                    <div>
                      <p className="text-xs text-muted-foreground">Signals fired</p>
                      <p className="font-mono text-lg tabular-nums">
                        {state.result.firedSignals}
                        <span className="text-sm text-muted-foreground">
                          {' '}
                          / {state.result.evaluatedSignals}
                        </span>
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Weighted score</p>
                      <p className="font-mono text-lg tabular-nums">
                        {state.result.weightedScore.toFixed(1)}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Duration</p>
                      <p className="font-mono text-lg tabular-nums">
                        {(state.result.durationMs / 1000).toFixed(1)}s
                      </p>
                    </div>
                  </div>

                  <ConfidenceMeter value={state.result.confidence} />

                  {state.result.hardTriggers.length > 0 ? (
                    <ul className="space-y-1">
                      {state.result.hardTriggers.map((trigger) => (
                        <li
                          key={trigger.id}
                          className="flex items-start gap-2 text-sm text-verdict-likely-malicious-accent"
                        >
                          <AlertTriangle aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
                          {trigger.label}
                        </li>
                      ))}
                    </ul>
                  ) : null}

                  {state.result.partial ? (
                    <p className="text-xs text-muted-foreground">
                      One or more families did not complete. This verdict is partial and its
                      confidence is reduced accordingly.
                    </p>
                  ) : null}
                </div>
              ) : null}

              <div className="flex flex-wrap gap-2">
                <Button asChild size="sm" variant={state.result ? 'default' : 'outline'}>
                  <Link href={href}>Open report</Link>
                </Button>
                <Button asChild size="sm" variant="ghost">
                  <Link href={`/analyses/${scan.analysisId}`}>Analysis record</Link>
                </Button>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
