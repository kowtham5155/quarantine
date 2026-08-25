import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowRight } from 'lucide-react';

import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { SIGNAL_FAMILIES, SIGNAL_FAMILY_META, VERDICTS, VERDICT_META } from '@/lib/constants';
import { HARD_TRIGGERS } from '@/lib/engine/verdict';
import { getRuleCatalogue } from '@/lib/services/catalogue.service';

export const metadata: Metadata = {
  title: 'How it works',
  description:
    'The detection methodology: what the engine downloads, what it reads, how signals are weighted, and when a single signal is dispositive.',
};

const PIPELINE = [
  {
    stage: 'Metadata',
    detail:
      'Registry metadata for the exact version: declared scripts, dependencies, maintainers, publish times, download counts, repository URL. Attacker-controlled except the timestamps.',
  },
  {
    stage: 'Download',
    detail:
      'The published tarball, fetched through an SSRF-guarded client: DNS resolved first, private ranges rejected, 10s timeout, at most three redirects, fixed User-Agent.',
  },
  {
    stage: 'Extraction',
    detail:
      'Bounded: 50MB total, 10,000 entries, 10MB per file, depth 20, and every entry path resolved against the extraction root so a zip-slip entry cannot escape it.',
  },
  {
    stage: 'Repository',
    detail:
      'Where a repository is declared, the git tag matching the version is fetched and normalised into a path-to-hash map for provenance comparison.',
  },
  {
    stage: 'Signals',
    detail:
      'Six family modules run in parallel against a wall-clock budget. A family that fails is recorded as incomplete rather than failing the analysis — five families of evidence beats none.',
  },
  {
    stage: 'Verdict',
    detail:
      'Hard triggers first, then weighted evidence, then a confidence figure derived from corroboration and how much of the package was actually inspected.',
  },
] as const;

export default async function HowItWorksPage() {
  const catalogue = await getRuleCatalogue();

  return (
    <div className="space-y-16">
      <header className="max-w-3xl space-y-4">
        <p className="font-mono text-xs tracking-widest text-primary uppercase">Methodology</p>
        <h1 className="text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
          What the engine actually does to a package
        </h1>
        <p className="text-base text-muted-foreground">
          Quarantine is a static analyser with a hard rule at its centre: package contents are never
          executed, required, imported or evaluated. Everything below happens by parsing text and
          reading bytes.
        </p>
      </header>

      <section aria-labelledby="pipeline" className="space-y-5">
        <h2 id="pipeline" className="text-2xl font-semibold tracking-tight">
          The pipeline
        </h2>
        <ol className="space-y-3">
          {PIPELINE.map((step, index) => (
            <li key={step.stage} className="flex gap-4 rounded-lg border border-border p-4">
              <span className="mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-full border border-border font-mono text-xs text-muted-foreground">
                {index + 1}
              </span>
              <div className="min-w-0 space-y-1">
                <h3 className="text-sm font-semibold">{step.stage}</h3>
                <p className="text-sm text-muted-foreground">{step.detail}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section aria-labelledby="families" className="space-y-5">
        <div className="max-w-3xl space-y-2">
          <h2 id="families" className="text-2xl font-semibold tracking-tight">
            The six families
          </h2>
          <p className="text-sm text-muted-foreground">
            {catalogue.total} rules, {catalogue.enabled} of them enabled. Each family is scored
            independently so that one noisy family cannot carry a verdict on its own.
          </p>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          {SIGNAL_FAMILIES.map((family) => {
            const meta = SIGNAL_FAMILY_META[family];
            const count = catalogue.byFamily.find((row) => row.family === family)?.count ?? 0;
            return (
              <Card key={family}>
                <CardHeader>
                  <CardTitle className="flex flex-wrap items-center gap-2 text-base">
                    {meta.label}
                    <span className="font-mono text-xs font-normal text-muted-foreground">
                      {count} rules · {meta.prefix}-*
                    </span>
                  </CardTitle>
                  <CardDescription>{meta.description}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  <ul className="space-y-1.5 text-sm text-muted-foreground">
                    {catalogue.rules
                      .filter((rule) => rule.family === family)
                      .slice(0, 4)
                      .map((rule) => (
                        <li key={rule.ruleId} className="flex gap-2">
                          <code className="shrink-0 font-mono text-xs text-foreground">
                            {rule.ruleId}
                          </code>
                          <span className="min-w-0">{rule.name}</span>
                        </li>
                      ))}
                  </ul>
                  <Link
                    href={`/detections?family=${family}`}
                    className="inline-flex items-center gap-1 text-sm text-primary underline-offset-4 hover:underline"
                  >
                    All {count} rules
                    <ArrowRight aria-hidden="true" className="size-3.5" />
                  </Link>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </section>

      <section aria-labelledby="context" className="space-y-4">
        <h2 id="context" className="text-2xl font-semibold tracking-tight">
          Capability is contextual
        </h2>
        <div className="max-w-3xl space-y-3 text-sm text-muted-foreground">
          <p>
            <code className="font-mono text-foreground">child_process</code> in a build tool is
            normal. The same import in a string-formatting utility is an alarm. The engine derives a
            declared-purpose bucket from metadata alone — name, description, keywords, dependencies
            — and applies it as a multiplier to the capability family, so the same evidence scores
            differently depending on what the package claims to be.
          </p>
          <p>
            This is the modifier a signature scanner cannot apply, and it is recorded per signal so
            a report can show the arithmetic rather than asserting a number.
          </p>
        </div>
      </section>

      <section aria-labelledby="verdict" className="space-y-5">
        <h2 id="verdict" className="text-2xl font-semibold tracking-tight">
          Hard triggers, then weighted evidence
        </h2>
        <div className="max-w-3xl space-y-3 text-sm text-muted-foreground">
          <p>
            A linear 0–100 score is the wrong abstraction on its own: some single findings are
            dispositive regardless of everything else. An install script that decodes a payload and
            POSTs your environment to a hardcoded IP is malicious no matter how healthy the
            maintainer history looks.
          </p>
          <p>
            So the model is hybrid. Each combination below forces a minimum verdict of{' '}
            <VerdictBadge verdict="LIKELY_MALICIOUS" size="sm" />. Everything else is scored: weight
            × confidence × context modifier, summed, then bucketed.
          </p>
        </div>

        <div className="space-y-3">
          {HARD_TRIGGERS.map((trigger) => (
            <div key={trigger.id} className="rounded-lg border border-border p-4">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-sm font-semibold">{trigger.label}</h3>
                <code className="font-mono text-xs text-muted-foreground">{trigger.id}</code>
              </div>
              <p className="mt-2 text-sm text-muted-foreground">{trigger.rationale}</p>
            </div>
          ))}
        </div>

        <Separator />

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {VERDICTS.map((verdict) => (
            <div key={verdict} className="rounded-lg border border-border p-4">
              <VerdictBadge verdict={verdict} appearance="solid" />
              <p className="mt-3 text-sm text-muted-foreground">
                {VERDICT_META[verdict].description}
              </p>
            </div>
          ))}
        </div>
      </section>

      <section aria-labelledby="limits" className="space-y-4">
        <h2 id="limits" className="text-2xl font-semibold tracking-tight">
          What it does not do
        </h2>
        <ul className="max-w-3xl list-disc space-y-2 pl-5 text-sm text-muted-foreground">
          <li>
            <strong className="text-foreground">No dynamic analysis.</strong> Nothing is executed in
            a sandbox. Doing that badly is worse than not doing it, and doing it well needs
            isolation infrastructure this deployment does not have.
          </li>
          <li>
            <strong className="text-foreground">No CVE matching.</strong> A known vulnerability in a
            legitimate package is a different problem, already well served.
          </li>
          <li>
            <strong className="text-foreground">No private registries.</strong> Only public
            artefacts, fetched from the public registry.
          </li>
          <li>
            <strong className="text-foreground">No claim of completeness.</strong> Confidence is
            reported alongside every verdict precisely because a partial analysis is a weaker
            statement than a complete one.
          </li>
        </ul>
      </section>

      <div className="flex flex-wrap gap-3">
        <Button asChild>
          <Link href="/scan">Scan a package</Link>
        </Button>
        <Button asChild variant="outline">
          <Link href="/research">Evaluation results</Link>
        </Button>
        <Button asChild variant="outline">
          <Link href="/security">How we handle malware safely</Link>
        </Button>
      </div>
    </div>
  );
}
