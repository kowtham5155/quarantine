import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { AlertTriangle } from 'lucide-react';

import { ConfidenceMeter } from '@/components/shared/ConfidenceMeter';
import { PackageRef } from '@/components/shared/PackageRef';
import { PageHeader } from '@/components/shared/PageHeader';
import { SignalBadge } from '@/components/shared/SignalBadge';
import { TimeAgo } from '@/components/shared/TimeAgo';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { requireAuthContext } from '@/lib/auth-context';
import { isVerdict, SIGNAL_FAMILIES, SIGNAL_FAMILY_META } from '@/lib/constants';
import { NotFoundError } from '@/lib/errors';
import { ecosystemSlug, versionHref } from '@/lib/routes';
import { safeText } from '@/lib/safe-display';
import { getAnalysis } from '@/lib/services/analysis.service';
import { hardTriggerDetail } from '@/lib/services/package.service';

import { RunNow } from './RunNow';

interface PageProps {
  params: Promise<{ id: string }>;
}

export const metadata: Metadata = { title: 'Analysis' };

export default async function AnalysisDetailPage({ params }: PageProps) {
  const ctx = await requireAuthContext();
  const { id } = await params;

  let analysis;
  try {
    analysis = await getAnalysis({ ...ctx, actorEmail: ctx.email }, id);
  } catch (error) {
    if (error instanceof NotFoundError) notFound();
    throw error;
  }

  const pkg = analysis.packageVersion.package;
  const verdict = isVerdict(analysis.verdict) ? analysis.verdict : null;
  const runnable = analysis.status === 'QUEUED' || analysis.status === 'FAILED';
  const firedRules = new Set(analysis.signalHits.map((hit) => hit.ruleId));
  const triggers = hardTriggerDetail(analysis.hardTriggersFired);

  return (
    <div className="space-y-8">
      <PageHeader
        breadcrumbs={[{ label: 'Analyses', href: '/analyses' }, { label: 'Record' }]}
        title="Analysis record"
        description="One run of the engine: what it was asked to look at, what happened, and what it produced."
        meta={
          <>
            <PackageRef
              name={pkg.name}
              version={analysis.packageVersion.version}
              ecosystem={ecosystemSlug(pkg.ecosystem)}
              href={versionHref(pkg.ecosystem, pkg.name, analysis.packageVersion.version)}
            />
            <Badge variant={analysis.status === 'FAILED' ? 'destructive' : 'secondary'}>
              {analysis.status}
            </Badge>
            {verdict ? <VerdictBadge verdict={verdict} size="sm" /> : null}
          </>
        }
        actions={
          <Button asChild variant="outline">
            <Link href={versionHref(pkg.ecosystem, pkg.name, analysis.packageVersion.version)}>
              Open report
            </Link>
          </Button>
        }
      />

      {analysis.errorMessage ? (
        <p
          role="alert"
          className="flex items-start gap-2 rounded-lg border border-verdict-suspicious-accent/40 bg-verdict-suspicious-surface p-4 text-sm text-verdict-suspicious-accent"
        >
          <AlertTriangle aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          {safeText(analysis.errorMessage, { maxLength: 400 })}
        </p>
      ) : null}

      {runnable ? (
        <RunNow
          scan={{
            analysisId: analysis.id,
            ecosystem: pkg.ecosystem,
            name: pkg.name,
            version: analysis.packageVersion.version,
            reused: false,
          }}
        />
      ) : null}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Run</CardTitle>
            <CardDescription>Timings and the engine build that produced this.</CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid gap-4 sm:grid-cols-2">
              <div>
                <dt className="text-xs text-muted-foreground">Queued</dt>
                <dd className="text-sm">
                  <TimeAgo date={analysis.createdAt} />
                </dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Started</dt>
                <dd className="text-sm">
                  {analysis.startedAt ? <TimeAgo date={analysis.startedAt} /> : '—'}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Completed</dt>
                <dd className="text-sm">
                  {analysis.completedAt ? <TimeAgo date={analysis.completedAt} /> : '—'}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Duration</dt>
                <dd className="font-mono text-sm tabular-nums">
                  {analysis.durationMs === null
                    ? '—'
                    : `${(analysis.durationMs / 1000).toFixed(2)}s`}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Engine version</dt>
                <dd className="font-mono text-sm">{analysis.engineVersion}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Files with evidence</dt>
                <dd className="font-mono text-sm tabular-nums">{analysis.filesAnalysed}</dd>
              </div>
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Outcome</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <p className="text-xs text-muted-foreground">Weighted score</p>
              <p className="font-mono text-2xl tabular-nums">
                {analysis.weightedScore === null ? '—' : analysis.weightedScore.toFixed(1)}
              </p>
            </div>
            <ConfidenceMeter value={analysis.confidence ?? 0} />
            <p className="text-xs text-muted-foreground">
              {firedRules.size} rules fired across {analysis.signalHits.length} recorded
              occurrences.
            </p>
          </CardContent>
        </Card>
      </div>

      {triggers.length > 0 ? (
        <Card className="border-verdict-likely-malicious-accent/40">
          <CardHeader>
            <CardTitle className="text-base">Hard triggers</CardTitle>
            <CardDescription>
              Combinations that force a minimum verdict regardless of the weighted score.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {triggers.map((trigger) => (
                <li key={trigger.id} className="text-sm">
                  <span className="font-medium text-verdict-likely-malicious-accent">
                    {trigger.label}
                  </span>
                  <p className="text-muted-foreground">{trigger.rationale}</p>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Signals by family</CardTitle>
          <CardDescription>Rules that fired, grouped by the family that owns them.</CardDescription>
        </CardHeader>
        <CardContent>
          {analysis.signalHits.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No signal fired in this run.
              {analysis.status === 'COMPLETED'
                ? ' Every enabled rule was evaluated and none matched.'
                : ''}
            </p>
          ) : (
            <ul className="space-y-3">
              {SIGNAL_FAMILIES.map((family) => {
                const rules = [
                  ...new Set(
                    analysis.signalHits
                      .filter((hit) => hit.family === family)
                      .map((hit) => hit.ruleId),
                  ),
                ].sort();
                if (rules.length === 0) return null;

                return (
                  <li key={family} className="flex flex-wrap items-center gap-2">
                    <SignalBadge family={family} />
                    <span className="text-xs text-muted-foreground">
                      {SIGNAL_FAMILY_META[family].description}
                    </span>
                    <span className="ml-auto flex flex-wrap gap-1">
                      {rules.map((ruleId) => (
                        <code
                          key={ruleId}
                          className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]"
                        >
                          {ruleId}
                        </code>
                      ))}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </CardContent>
      </Card>

      {analysis.typosquatMatches.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Typosquat matches</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1.5">
              {analysis.typosquatMatches.map((match) => (
                <li key={match.id} className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="break-anywhere font-mono text-xs">
                    {safeText(match.targetPackage, { maxLength: 120 })}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    distance {match.distance} · {safeText(match.technique, { maxLength: 60 })} ·{' '}
                    {match.targetDownloads.toLocaleString('en-GB')} weekly downloads
                  </span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
