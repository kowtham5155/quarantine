import { z } from 'zod';

import { requestFingerprint, requireAuthContext } from '@/lib/auth-context';
import { ValidationError } from '@/lib/errors';
import { errorResponse, requireSameOrigin } from '@/lib/http';
import { CORRELATION_ID_HEADER, loggerForRequest } from '@/lib/logger';
import { bucketKey, enforce } from '@/lib/rate-limit';
import { assertAnalysisRunnable, runAnalysis } from '@/lib/services/analysis.service';
import type { ProgressEvent } from '@/lib/engine';

/**
 * POST /api/analyses/[id]/run — run a queued analysis, streaming progress.
 *
 * ## Why this is a Route Handler and not a Server Action
 *
 * CLAUDE.md reserves Route Handlers for webhooks, cron, the CLI and the public
 * API, and mutations otherwise go through Server Actions. This is the one case
 * a Server Action cannot express: an analysis takes tens of seconds, and a
 * Server Action returns exactly once, at the end. Watching a scan progress
 * stage by stage needs a streaming response body.
 *
 * ## The response
 *
 * NDJSON — one JSON object per line, flushed as it happens:
 *
 *   {"event":"accepted","analysisId":"…","package":{…}}
 *   {"event":"progress","stage":"download","status":"completed","elapsedMs":812}
 *   {"event":"result","verdict":"SUSPICIOUS","confidence":0.71,…}
 *
 * A failure that happens after the body has opened arrives as a final
 * `{"event":"error"}` line, because the status code is long committed by then.
 * Failures found before that — no such analysis, wrong org, already running —
 * come back as ordinary HTTP errors with the usual public error shape.
 *
 * ## Disconnects
 *
 * The engine run is not cancelled when the client goes away. The analysis is
 * persisted by `runAnalysis` regardless of who is listening, and abandoning a
 * half-finished scan would leave the row RUNNING with nothing to complete it.
 * Writes to a closed stream are swallowed rather than allowed to reject.
 *
 * SAFETY: nothing on this path executes package content. It calls the engine,
 * which parses and reads bytes; the temp directory the engine extracts into is
 * removed in a `finally` inside `withScanDirectory` on every exit path.
 */

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const paramsSchema = z.object({
  id: z.string().min(1).max(64),
});

interface RouteContext {
  params: Promise<{ id: string }>;
}

export async function POST(request: Request, context: RouteContext): Promise<Response> {
  const { logger, correlationId } = loggerForRequest(request.headers, {
    route: '/api/analyses/[id]/run',
  });

  try {
    requireSameOrigin(request);

    const ctx = await requireAuthContext();
    const { ip } = await requestFingerprint();

    const parsed = paramsSchema.safeParse(await context.params);
    if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);
    const analysisId = parsed.data.id;

    // A scan is expensive — a tarball download, extraction and six analysis
    // families — so the limit is per user *and* per org: one impatient client
    // must not spend the org's budget, and one org must not spend the host's.
    await enforce('scanCreate', bucketKey('scanCreate', { org: ctx.orgId, user: ctx.userId }));
    await enforce('scanCreate', bucketKey('scanCreate', { org: ctx.orgId, ip }));

    const runnable = await assertAnalysisRunnable(ctx, analysisId);

    const runLogger = logger.child({ scanId: analysisId, orgId: ctx.orgId, userId: ctx.userId });
    const encoder = new TextEncoder();

    const stream = new ReadableStream<Uint8Array>({
      async start(controller) {
        let open = true;

        /** Write one NDJSON line, tolerating a client that has already left. */
        const send = (payload: Record<string, unknown>): void => {
          if (!open) return;
          try {
            controller.enqueue(encoder.encode(`${JSON.stringify(payload)}\n`));
          } catch {
            open = false;
          }
        };

        send({
          event: 'accepted',
          analysisId,
          // Package-derived strings. Transported as JSON data and escaped by
          // the client on render; never interpolated into markup here.
          package: {
            ecosystem: runnable.ecosystem,
            name: runnable.name,
            version: runnable.version,
          },
        });

        const onProgress = (progress: ProgressEvent): void => {
          send({ event: 'progress', ...progress });
        };

        try {
          const result = await runAnalysis({ ...ctx, actorEmail: ctx.email }, analysisId, {
            onProgress,
          });

          if (result) {
            send({
              event: 'result',
              analysisId,
              verdict: result.verdict,
              confidence: result.confidence,
              weightedScore: result.weightedScore,
              partial: result.partial,
              durationMs: result.durationMs,
              hardTriggers: result.hardTriggers.map((trigger) => ({
                id: trigger.id,
                label: trigger.label,
                ruleIds: trigger.ruleIds,
              })),
              firedSignals: result.signals.filter((signal) => signal.fired).length,
              evaluatedSignals: result.signals.length,
              incompleteStages: result.incompleteStages,
            });
          } else {
            // `runAnalysis` records the failure on the row and returns null
            // rather than throwing: the run happened, and not being able to
            // reach the registry is its outcome.
            send({
              event: 'error',
              code: 'ANALYSIS_ERROR',
              message: 'The analysis could not be completed. See the analysis for detail.',
            });
          }
        } catch (error) {
          runLogger.error({ err: error }, 'streamed analysis failed');
          send({
            event: 'error',
            code: 'INTERNAL_ERROR',
            message: 'The analysis could not be completed.',
          });
        } finally {
          open = false;
          try {
            controller.close();
          } catch {
            // Already closed by the client going away.
          }
        }
      },
    });

    return new Response(stream, {
      status: 200,
      headers: {
        'content-type': 'application/x-ndjson; charset=utf-8',
        'cache-control': 'no-store, no-transform',
        'x-content-type-options': 'nosniff',
        // Proxies that buffer would defeat the point of streaming.
        'x-accel-buffering': 'no',
        [CORRELATION_ID_HEADER]: correlationId,
      },
    });
  } catch (error) {
    return errorResponse(error, correlationId);
  }
}
