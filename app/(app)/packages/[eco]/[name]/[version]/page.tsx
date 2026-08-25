import Link from 'next/link';
import { AlertTriangle, FileCode2, Scale, ShieldCheck } from 'lucide-react';

import { CodeViewer } from '@/components/shared/CodeViewer';
import { ConfidenceMeter } from '@/components/shared/ConfidenceMeter';
import { EmptyState } from '@/components/shared/EmptyState';
import { SignalBadge } from '@/components/shared/SignalBadge';
import { TimeAgo } from '@/components/shared/TimeAgo';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { SIGNAL_FAMILY_META, VERDICT_META } from '@/lib/constants';
import { versionHref } from '@/lib/routes';
import { safeText, shortHash } from '@/lib/safe-display';

import { readVersionParams } from '../../../params';
import { loadReport } from './report';

interface PageProps {
  params: Promise<{ eco: string; name: string; version: string }>;
}

function formatBytes(bytes: number | null): string {
  if (bytes === null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} kB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default async function VersionReportPage({ params }: PageProps) {
  const { ecosystem, name, version } = await readVersionParams(params);
  const report = await loadReport(ecosystem, name, version);

  const verdict = report.analysis.verdict;
  const meta = verdict ? VERDICT_META[verdict] : null;

  // One entry per rule that fired, ranked by what it actually contributed.
  const byRule = new Map<string, (typeof report.hits)[number][]>();
  for (const hit of report.hits) {
    const existing = byRule.get(hit.ruleId);
    if (existing) existing.push(hit);
    else byRule.set(hit.ruleId, [hit]);
  }

  const ranked = [...byRule.entries()]
    .map(([ruleId, hits]) => {
      const first = hits[0];
      const contribution = first ? first.weight * first.confidence * first.contextModifier : 0;
      return { ruleId, hits, contribution };
    })
    .sort((a, b) => b.contribution - a.contribution);

  const maxContribution = report.families.reduce(
    (best, family) => Math.max(best, family.contribution),
    0,
  );

  return (
    <div className="space-y-6">
      <section
        aria-labelledby="verdict"
        className="rounded-xl border border-border bg-surface/50 p-5 sm:p-6"
      >
        <div className="grid gap-6 lg:grid-cols-[2fr_1fr]">
          <div className="space-y-3">
            <h2
              id="verdict"
              className="text-xs font-semibold tracking-wide text-muted-foreground uppercase"
            >
              Verdict
            </h2>
            {verdict && meta ? (
              <>
                <p className={`text-3xl font-semibold tracking-tight ${meta.textClass}`}>
                  {meta.label}
                </p>
                <p className="max-w-prose text-sm text-muted-foreground">{meta.description}</p>
              </>
            ) : (
              <>
                <p className="text-3xl font-semibold tracking-tight">{report.analysis.status}</p>
                <p className="max-w-prose text-sm text-muted-foreground">
                  {report.analysis.errorMessage
                    ? safeText(report.analysis.errorMessage, { maxLength: 300 })
                    : 'This analysis has not produced a verdict yet.'}
                </p>
              </>
            )}

            <dl className="grid gap-3 pt-2 sm:grid-cols-3">
              <div>
                <dt className="text-xs text-muted-foreground">Weighted score</dt>
                <dd className="font-mono text-lg tabular-nums">
                  {report.analysis.weightedScore === null
                    ? '—'
                    : report.analysis.weightedScore.toFixed(1)}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Rules fired</dt>
                <dd className="font-mono text-lg tabular-nums">
                  {byRule.size}
                  <span className="text-sm text-muted-foreground"> / {report.rules.length}</span>
                </dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Analysis time</dt>
                <dd className="font-mono text-lg tabular-nums">
                  {report.analysis.durationMs === null
                    ? '—'
                    : `${(report.analysis.durationMs / 1000).toFixed(1)}s`}
                </dd>
              </div>
            </dl>
          </div>

          <div className="space-y-4">
            <ConfidenceMeter value={report.analysis.confidence ?? 0} />
            <p className="text-xs text-muted-foreground">
              Confidence is how much of the package the engine inspected and how well the fired
              signals corroborate each other — not how bad the verdict is.
            </p>
            {report.analysis.completedAt ? (
              <p className="text-xs text-muted-foreground">
                Completed <TimeAgo date={report.analysis.completedAt} />
              </p>
            ) : null}
          </div>
        </div>
      </section>

      {report.hardTriggers.length > 0 ? (
        <section aria-labelledby="hard-triggers" className="space-y-3">
          <h2
            id="hard-triggers"
            className="flex items-center gap-2 text-sm font-semibold tracking-wide uppercase"
          >
            <AlertTriangle
              aria-hidden="true"
              className="size-4 text-verdict-likely-malicious-accent"
            />
            Hard triggers fired
          </h2>
          <div className="space-y-3">
            {report.hardTriggers.map((trigger) => (
              <div
                key={trigger.id}
                className="rounded-lg border border-verdict-likely-malicious-accent/40 bg-verdict-likely-malicious-surface p-4"
              >
                <p className="text-sm font-semibold text-verdict-likely-malicious-accent">
                  {trigger.label}
                </p>
                <p className="mt-1.5 text-sm text-muted-foreground">{trigger.rationale}</p>
              </div>
            ))}
          </div>
        </section>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Scale aria-hidden="true" className="size-4 text-muted-foreground" />
              Signal families
            </CardTitle>
            <CardDescription>
              Each family&apos;s contribution to the weighted score: weight × confidence × context
              modifier, counted once per rule.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-3">
              {report.families.map((family) => {
                const familyMeta = SIGNAL_FAMILY_META[family.family];
                const width =
                  maxContribution === 0 ? 0 : (family.contribution / maxContribution) * 100;

                return (
                  <li key={family.family} className="space-y-1.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <SignalBadge family={family.family} />
                      <span className="font-mono text-xs text-muted-foreground tabular-nums">
                        <span className="text-foreground">{family.fired}</span>/{family.evaluated}{' '}
                        rules · {family.contribution.toFixed(1)}
                      </span>
                    </div>
                    <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${width}%`,
                          backgroundColor: familyMeta.hex,
                        }}
                      />
                    </div>
                  </li>
                );
              })}
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Artefact</CardTitle>
            <CardDescription>What was downloaded and inspected.</CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="space-y-3 text-sm">
              <div className="flex justify-between gap-3">
                <dt className="text-muted-foreground">Published</dt>
                <dd className="font-mono text-xs">
                  {report.version.publishedAt
                    ? report.version.publishedAt.toISOString().slice(0, 10)
                    : '—'}
                </dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-muted-foreground">Unpacked size</dt>
                <dd className="font-mono text-xs">{formatBytes(report.version.unpackedSize)}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-muted-foreground">Files</dt>
                <dd className="font-mono text-xs">{report.version.fileCount ?? '—'}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-muted-foreground">Install scripts</dt>
                <dd className="font-mono text-xs">
                  {report.version.hasInstallScripts ? 'present' : 'none'}
                </dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-muted-foreground">Provenance attestation</dt>
                <dd className="font-mono text-xs">
                  {report.version.provenanceAttested ? 'signed' : 'absent'}
                </dd>
              </div>
              {report.version.integrity ? (
                <div className="space-y-1">
                  <dt className="text-muted-foreground">Registry integrity</dt>
                  <dd className="break-anywhere font-mono text-xs">
                    {shortHash(safeText(report.version.integrity, { maxLength: 120 }), 24)}
                  </dd>
                </div>
              ) : null}
              <div className="flex justify-between gap-3">
                <dt className="text-muted-foreground">Weekly downloads</dt>
                <dd className="font-mono text-xs">
                  {report.package.weeklyDownloads.toLocaleString('en-GB')}
                </dd>
              </div>
            </dl>
          </CardContent>
        </Card>
      </div>

      <section aria-labelledby="top-signals" className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 id="top-signals" className="text-sm font-semibold tracking-wide uppercase">
            Top signals
          </h2>
          <Button asChild variant="outline" size="sm">
            <Link href={versionHref(ecosystem, name, version, 'signals')}>
              Every rule, fired and not fired
            </Link>
          </Button>
        </div>

        {ranked.length === 0 ? (
          <EmptyState
            icon={ShieldCheck}
            title="No signal fired"
            description="Every enabled rule was evaluated and none matched. Check the confidence figure: a clean verdict on a partial analysis is a weaker statement than one on a complete pass."
          />
        ) : (
          <div className="space-y-4">
            {ranked.slice(0, 6).map((entry) => {
              const rule = report.rules.find((candidate) => candidate.ruleId === entry.ruleId);
              const first = entry.hits[0];
              const withExcerpt = entry.hits.find((hit) => hit.excerpt !== null);

              return (
                <Card key={entry.ruleId}>
                  <CardHeader className="gap-2">
                    <CardTitle className="flex flex-wrap items-center gap-2 text-base">
                      <SignalBadge family={first?.family ?? 'INSTALL'} ruleId={entry.ruleId} />
                      <span>{rule?.name ?? entry.ruleId}</span>
                    </CardTitle>
                    <CardDescription>{rule?.description}</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="flex flex-wrap gap-x-6 gap-y-1 font-mono text-xs text-muted-foreground">
                      <span>weight {first?.weight.toFixed(1) ?? '—'}</span>
                      <span>confidence {((first?.confidence ?? 0) * 100).toFixed(0)}%</span>
                      <span>context ×{first?.contextModifier.toFixed(2) ?? '1.00'}</span>
                      <span>
                        contribution {entry.contribution.toFixed(2)} · {entry.hits.length}{' '}
                        {entry.hits.length === 1 ? 'occurrence' : 'occurrences'}
                      </span>
                    </div>

                    {withExcerpt?.excerpt ? (
                      <CodeViewer
                        code={withExcerpt.excerpt}
                        filename={withExcerpt.filePath ?? undefined}
                        startLine={withExcerpt.lineStart ?? 1}
                        maxLines={20}
                        showCopy={false}
                        highlights={
                          withExcerpt.lineStart
                            ? [
                                {
                                  startLine: withExcerpt.lineStart,
                                  endLine: withExcerpt.lineEnd ?? withExcerpt.lineStart,
                                  severity: 'critical',
                                  label: entry.ruleId,
                                },
                              ]
                            : []
                        }
                      />
                    ) : first?.filePath ? (
                      <p className="flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
                        <FileCode2 aria-hidden="true" className="size-3.5" />
                        {safeText(first.filePath, { maxLength: 160 })}
                      </p>
                    ) : null}

                    {rule?.remediation ? (
                      <p className="text-sm text-muted-foreground">
                        <span className="font-medium text-foreground">Remediation.</span>{' '}
                        {rule.remediation}
                      </p>
                    ) : null}
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
