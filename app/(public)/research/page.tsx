import type { Metadata } from 'next';
import Link from 'next/link';
import { FlaskConical } from 'lucide-react';

import { EmptyState } from '@/components/shared/EmptyState';
import { PageHeader } from '@/components/shared/PageHeader';
import { StatCard } from '@/components/shared/StatCard';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { SIGNAL_FAMILY_META, type SignalFamily } from '@/lib/constants';
import { getEvaluationSummary } from '@/lib/services/catalogue.service';

import { FamilyMetricsChart } from './FamilyMetricsChart';

export const metadata: Metadata = {
  title: 'Research',
  description:
    'Evaluation results against a labelled corpus: precision, recall, false-positive rate, per-family breakdown, latency and corpus composition.',
};

function percent(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—';
  return `${(value * 100).toFixed(1)}%`;
}

export default async function ResearchPage() {
  const { latest, history, corpus } = await getEvaluationSummary();

  return (
    <div className="space-y-10">
      <PageHeader
        title="Evaluation"
        description="A supply chain scanner that cries wolf gets disabled in week two. These are the numbers the engine actually produces against a labelled corpus, including the ones that are not flattering."
      />

      {latest === null ? (
        <EmptyState
          icon={FlaskConical}
          title="No evaluation run has been recorded yet"
          description="The corpus is seeded but the engine has not been evaluated against it. Results appear here once an evaluation run completes."
          footer={
            <>
              The corpus currently holds {corpus.total} labelled entries — {corpus.malicious}{' '}
              malicious, {corpus.clean} clean.
            </>
          }
        />
      ) : (
        <>
          <section aria-labelledby="headline" className="space-y-4">
            <h2 id="headline" className="sr-only">
              Headline metrics
            </h2>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <StatCard
                label="Precision"
                value={percent(latest.precision)}
                hint="of flagged packages that were malicious"
              />
              <StatCard
                label="Recall"
                value={percent(latest.recall)}
                hint="of malicious packages that were flagged"
              />
              <StatCard label="F1" value={latest.f1.toFixed(2)} hint="harmonic mean" />
              <StatCard
                label="False-positive rate"
                value={percent(latest.falsePositiveRate)}
                hint="of clean packages wrongly flagged"
              />
            </div>
            <p className="text-xs text-muted-foreground">
              Engine {latest.engineVersion} · corpus of {latest.corpusSize} package versions · run{' '}
              {latest.ranAt.toISOString().slice(0, 10)}
            </p>
          </section>

          <section aria-labelledby="confusion" className="space-y-4">
            <div className="max-w-3xl space-y-2">
              <h2 id="confusion" className="text-2xl font-semibold tracking-tight">
                Confusion matrix
              </h2>
              <p className="text-sm text-muted-foreground">
                A package counts as flagged at{' '}
                <span className="font-medium text-foreground">SUSPICIOUS</span> or worse. The
                false-positive column is the one that decides whether anyone keeps the tool
                installed.
              </p>
            </div>

            <div className="overflow-x-auto rounded-lg border border-border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Ground truth</TableHead>
                    <TableHead className="text-right">Flagged</TableHead>
                    <TableHead className="text-right">Not flagged</TableHead>
                    <TableHead className="text-right">Total</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <TableRow>
                    <TableCell className="font-medium">Malicious</TableCell>
                    <TableCell className="text-right font-mono text-verdict-clean-accent tabular-nums">
                      {latest.truePositives}
                    </TableCell>
                    <TableCell className="text-right font-mono text-verdict-likely-malicious-accent tabular-nums">
                      {latest.falseNegatives}
                    </TableCell>
                    <TableCell className="text-right font-mono tabular-nums">
                      {latest.truePositives + latest.falseNegatives}
                    </TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell className="font-medium">Clean</TableCell>
                    <TableCell className="text-right font-mono text-verdict-suspicious-accent tabular-nums">
                      {latest.falsePositives}
                    </TableCell>
                    <TableCell className="text-right font-mono text-verdict-clean-accent tabular-nums">
                      {latest.trueNegatives}
                    </TableCell>
                    <TableCell className="text-right font-mono tabular-nums">
                      {latest.falsePositives + latest.trueNegatives}
                    </TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </div>
          </section>

          <section aria-labelledby="per-family" className="space-y-4">
            <div className="max-w-3xl space-y-2">
              <h2 id="per-family" className="text-2xl font-semibold tracking-tight">
                Per-family contribution
              </h2>
              <p className="text-sm text-muted-foreground">
                Which rules actually carry the model. Identity and maintainer forensics are the
                weakest families by precision, which is exactly what you would expect: both reason
                about circumstantial evidence rather than about what the code does.
              </p>
            </div>

            {latest.perFamily.length > 0 ? (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Precision and recall by family</CardTitle>
                  <CardDescription>
                    Measured on the same corpus as the headline figures.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <FamilyMetricsChart metrics={latest.perFamily} />

                  <div className="overflow-x-auto rounded-lg border border-border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Family</TableHead>
                          <TableHead className="text-right">Precision</TableHead>
                          <TableHead className="text-right">Recall</TableHead>
                          <TableHead className="text-right">F1</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {latest.perFamily.map((metric) => (
                          <TableRow key={metric.family}>
                            <TableCell className="font-medium">
                              {SIGNAL_FAMILY_META[metric.family as SignalFamily].label}
                            </TableCell>
                            <TableCell className="text-right font-mono tabular-nums">
                              {percent(metric.precision)}
                            </TableCell>
                            <TableCell className="text-right font-mono tabular-nums">
                              {percent(metric.recall)}
                            </TableCell>
                            <TableCell className="text-right font-mono tabular-nums">
                              {metric.f1 === null ? '—' : metric.f1.toFixed(2)}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </Card>
            ) : (
              <EmptyState
                size="sm"
                icon={FlaskConical}
                title="No per-family breakdown was recorded for this run"
                description="The run stored headline metrics only."
              />
            )}
          </section>

          <section aria-labelledby="latency" className="space-y-4">
            <h2 id="latency" className="text-2xl font-semibold tracking-tight">
              Latency
            </h2>
            <div className="grid gap-4 sm:grid-cols-2">
              <StatCard
                label="Mean analysis"
                value={`${(latest.meanLatencyMs / 1000).toFixed(1)}s`}
                hint="download, extraction and six families"
              />
              <StatCard
                label="p95 analysis"
                value={`${(latest.p95LatencyMs / 1000).toFixed(1)}s`}
                hint="the tail that decides CI viability"
              />
            </div>
          </section>

          {history.length > 1 ? (
            <section aria-labelledby="history" className="space-y-4">
              <div className="max-w-3xl space-y-2">
                <h2 id="history" className="text-2xl font-semibold tracking-tight">
                  Previous runs
                </h2>
                <p className="text-sm text-muted-foreground">
                  Kept as published. Tuning that improved one number at the expense of another is
                  the part worth being able to see.
                </p>
              </div>

              <div className="overflow-x-auto rounded-lg border border-border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Run</TableHead>
                      <TableHead>Engine</TableHead>
                      <TableHead className="text-right">Precision</TableHead>
                      <TableHead className="text-right">Recall</TableHead>
                      <TableHead className="text-right">FPR</TableHead>
                      <TableHead className="text-right">Corpus</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {history.map((run) => (
                      <TableRow key={run.id}>
                        <TableCell className="font-mono text-xs">
                          {run.ranAt.toISOString().slice(0, 10)}
                        </TableCell>
                        <TableCell className="font-mono text-xs">{run.engineVersion}</TableCell>
                        <TableCell className="text-right font-mono tabular-nums">
                          {percent(run.precision)}
                        </TableCell>
                        <TableCell className="text-right font-mono tabular-nums">
                          {percent(run.recall)}
                        </TableCell>
                        <TableCell className="text-right font-mono tabular-nums">
                          {percent(run.falsePositiveRate)}
                        </TableCell>
                        <TableCell className="text-right font-mono tabular-nums">
                          {run.corpusSize}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>

              {latest.notes ? (
                <p className="text-sm text-muted-foreground">
                  <span className="font-medium text-foreground">Note on the latest run:</span>{' '}
                  {latest.notes}
                </p>
              ) : null}
            </section>
          ) : null}
        </>
      )}

      <section aria-labelledby="corpus" className="space-y-4">
        <div className="max-w-3xl space-y-2">
          <h2 id="corpus" className="text-2xl font-semibold tracking-tight">
            Corpus composition
          </h2>
          <p className="text-sm text-muted-foreground">
            The negative class deliberately mixes popular and obscure packages. Typosquat detectors
            over-fire on obscure legitimate names, and a corpus of nothing but top-500 packages
            hides that completely.
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-3">
          <StatCard label="Labelled entries" value={corpus.total} />
          <StatCard label="Malicious" value={corpus.malicious} hint="published incident data" />
          <StatCard label="Clean" value={corpus.clean} hint="popular and long-tail" />
        </div>

        {corpus.sources.length > 0 ? (
          <div className="overflow-x-auto rounded-lg border border-border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Label source</TableHead>
                  <TableHead className="text-right">Entries</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {corpus.sources.map((source) => (
                  <TableRow key={source.source}>
                    <TableCell className="text-sm">{source.source}</TableCell>
                    <TableCell className="text-right font-mono tabular-nums">
                      {source.count}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : null}
      </section>

      <section aria-labelledby="methodology" className="space-y-4">
        <h2 id="methodology" className="text-2xl font-semibold tracking-tight">
          Methodology
        </h2>
        <ul className="max-w-3xl list-disc space-y-2 pl-5 text-sm text-muted-foreground">
          <li>
            <strong className="text-foreground">Positive class:</strong> known-malicious package
            versions from published supply-chain-attack datasets and incident disclosures, labelled
            by tarball hash where one is available — a name can be republished and a version can be
            re-tagged.
          </li>
          <li>
            <strong className="text-foreground">Negative class:</strong> high-download packages plus
            a sample of low-download packages, so the false-positive rate can be reported separately
            for popular and obscure names.
          </li>
          <li>
            <strong className="text-foreground">Flag threshold:</strong> SUSPICIOUS or worse. Moving
            the threshold moves precision and recall in opposite directions, and reporting one
            without naming the threshold is meaningless.
          </li>
          <li>
            <strong className="text-foreground">Latency</strong> is wall-clock per package version,
            end to end, including registry fetch and extraction.
          </li>
        </ul>
        <p className="text-sm text-muted-foreground">
          The rules behind these numbers are published in full on the{' '}
          <Link href="/detections" className="text-primary underline-offset-4 hover:underline">
            detection catalogue
          </Link>
          .
        </p>
      </section>
    </div>
  );
}
