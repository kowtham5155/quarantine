import { errorResponse, jsonResponse, requireCronSecret } from '@/lib/http';
import { loggerForRequest } from '@/lib/logger';
import { ANALYSIS_BUDGET_MS } from '@/lib/engine/thresholds';
import {
  claimQueuedAnalyses,
  reclaimStalledAnalyses,
  runAnalysis,
  systemContext,
} from '@/lib/services/analysis.service';

/**
 * GET|POST /api/cron/analyses — drain the analysis queue.
 *
 * ## Why a queue exists at all
 *
 * The interactive path runs an analysis inline in the request that asks for it,
 * because the deployment target is a single Render Web Service with no worker
 * process and no broker. That covers a developer watching a scan. It does not
 * cover the cases where nobody is watching: a CLI call that queued and hung up,
 * a project scan that expanded into forty package versions, an analysis whose
 * request was cut off mid-run. Those sit QUEUED until this endpoint picks them
 * up.
 *
 * ## Authentication
 *
 * A Bearer `CRON_SECRET`, compared in constant time. `/api/cron/*` is on the
 * middleware's self-authenticating list, so no session cookie reaches here and
 * there is no CSRF surface to protect: a browser cannot be tricked into
 * presenting a secret it does not have. GET is accepted because most schedulers
 * only send GET; POST is the honest verb and both do the same work.
 *
 * ## Bounded work
 *
 * One invocation runs at most `MAX_PER_SWEEP` analyses and stops accepting new
 * ones once `SWEEP_BUDGET_MS` has elapsed, so the request finishes well inside
 * any platform request timeout. Whatever is left stays QUEUED for the next
 * tick — the queue drains over time rather than one invocation trying to be
 * heroic and being killed halfway.
 */

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** Most analyses one sweep will start. */
const MAX_PER_SWEEP = 5;

/**
 * Wall-clock after which the sweep stops starting new analyses. Sized so that
 * the last analysis started can still use its full budget and finish inside a
 * conventional five-minute platform limit.
 */
const SWEEP_BUDGET_MS = 3 * 60_000;

/**
 * Age at which a RUNNING analysis is treated as dead rather than slow. Three
 * times the engine's own budget: a real run cannot legitimately exceed that.
 */
const STALL_AFTER_MS = ANALYSIS_BUDGET_MS * 3;

interface SweepSummary {
  claimed: number;
  completed: number;
  failed: number;
  reclaimed: number;
  remainingBudgetMs: number;
}

async function sweep(): Promise<SweepSummary> {
  const startedAt = Date.now();

  const reclaimed = await reclaimStalledAnalyses(STALL_AFTER_MS);
  const queued = await claimQueuedAnalyses(MAX_PER_SWEEP);

  let completed = 0;
  let failed = 0;

  for (const analysis of queued) {
    if (Date.now() - startedAt > SWEEP_BUDGET_MS) break;

    // The org comes from the analysis row, so the system context can only ever
    // act inside the tenant that already owns the work (CLAUDE.md rule 3).
    const ctx = systemContext(analysis.orgId);

    try {
      const result = await runAnalysis(ctx, analysis.id);
      if (result) {
        completed++;
      } else {
        failed++;
      }
    } catch {
      // `runAnalysis` already logged and recorded the failure on the row; a
      // throw here means the claim was lost to a concurrent run. Either way the
      // sweep continues — one bad package must not stall the queue.
      failed++;
    }
  }

  return {
    claimed: queued.length,
    completed,
    failed,
    reclaimed,
    remainingBudgetMs: Math.max(0, SWEEP_BUDGET_MS - (Date.now() - startedAt)),
  };
}

async function handle(request: Request): Promise<Response> {
  const { logger, correlationId } = loggerForRequest(request.headers, {
    route: '/api/cron/analyses',
  });

  try {
    requireCronSecret(request);

    const summary = await sweep();
    logger.info(summary, 'analysis sweep finished');

    return jsonResponse({ ok: true, ...summary });
  } catch (error) {
    return errorResponse(error, correlationId);
  }
}

export async function GET(request: Request): Promise<Response> {
  return handle(request);
}

export async function POST(request: Request): Promise<Response> {
  return handle(request);
}
