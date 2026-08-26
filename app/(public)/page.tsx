import Link from 'next/link';
import { ArrowRight, FileSearch, PackageSearch, ScanLine, TerminalSquare } from 'lucide-react';

import { SignalBadge } from '@/components/shared/SignalBadge';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { INCIDENTS } from '@/lib/content/incidents';
import { getRuleCatalogue } from '@/lib/services/catalogue.service';
import { SIGNAL_FAMILIES, SIGNAL_FAMILY_META, VERDICT_META, VERDICTS } from '@/lib/constants';

export default async function HomePage() {
  const catalogue = await getRuleCatalogue();

  return (
    <div className="space-y-24">
      <section className="max-w-3xl">
        <p className="mb-3 font-mono text-xs tracking-widest text-primary uppercase">
          Pre-install supply chain malware detection
        </p>
        <h1 className="text-3xl font-semibold tracking-tight text-balance sm:text-5xl">
          <code className="font-mono">npm audit</code> answers a different question than the one you
          are asking.
        </h1>
        <p className="mt-5 max-w-2xl text-base text-muted-foreground sm:text-lg">
          It matches names and versions against a CVE database, so it can only tell you about flaws
          somebody has already found, reported and published. Quarantine analyses the actual
          published tarball and returns a verdict <em>before</em> the package reaches a developer
          machine or a CI runner — six independent signal families, {catalogue.total} rules, purely
          static.
        </p>
        <div className="mt-8 flex flex-wrap items-center gap-3">
          <Button asChild size="lg">
            <Link href="/scan">
              <PackageSearch aria-hidden="true" />
              Scan a package
              <ArrowRight aria-hidden="true" />
            </Link>
          </Button>
          <Button asChild size="lg" variant="outline">
            <Link href="/how-it-works">
              <TerminalSquare aria-hidden="true" />
              Read the methodology
            </Link>
          </Button>
        </div>
      </section>

      <section aria-labelledby="blind-spot" className="space-y-5">
        <div className="max-w-3xl space-y-2">
          <h2 id="blind-spot" className="text-2xl font-semibold tracking-tight">
            The blind spot, four times over
          </h2>
          <p className="text-sm text-muted-foreground">
            A CVE only exists after someone has found, reported, triaged and published the flaw. For
            a deliberately malicious package, the entire point is to execute inside that window. In
            every incident below, <code className="font-mono">npm audit</code> returned zero
            findings at the moment of maximum exposure — while the evidence was sitting in the
            tarball.
          </p>
        </div>

        <div className="overflow-x-auto rounded-lg border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="min-w-40">Incident</TableHead>
                <TableHead className="min-w-72">Mechanism</TableHead>
                <TableHead className="min-w-40">Undetected for</TableHead>
                <TableHead className="min-w-64">Observable evidence</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {INCIDENTS.map((incident) => (
                <TableRow key={incident.package}>
                  <TableCell className="align-top">
                    <div className="font-mono text-sm">{incident.package}</div>
                    <div className="text-xs text-muted-foreground">{incident.year}</div>
                  </TableCell>
                  <TableCell className="align-top text-sm text-muted-foreground">
                    {incident.mechanism}
                  </TableCell>
                  <TableCell className="align-top font-mono text-sm whitespace-nowrap">
                    {incident.undetected}
                  </TableCell>
                  <TableCell className="align-top">
                    <p className="text-sm text-muted-foreground">{incident.evidence}</p>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {incident.families.map((family) => (
                        <SignalBadge key={family} family={family} />
                      ))}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </section>

      <section aria-labelledby="families" className="space-y-5">
        <div className="max-w-3xl space-y-2">
          <h2 id="families" className="text-2xl font-semibold tracking-tight">
            Six signal families
          </h2>
          <p className="text-sm text-muted-foreground">
            Each family answers a different question about the artefact. A verdict is what happens
            when they corroborate — or when one of them alone is dispositive.
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {SIGNAL_FAMILIES.map((family) => {
            const meta = SIGNAL_FAMILY_META[family];
            return (
              <Card key={family} className="h-full">
                <CardHeader>
                  <CardTitle className="text-base">{meta.label}</CardTitle>
                  <CardDescription>{meta.description}</CardDescription>
                </CardHeader>
                <CardContent>
                  <SignalBadge family={family} ruleId={`${meta.prefix}-001`} compact />
                </CardContent>
              </Card>
            );
          })}
        </div>

        <p className="text-sm text-muted-foreground">
          <Link href="/detections" className="text-primary underline-offset-4 hover:underline">
            Browse all {catalogue.total} rules
          </Link>{' '}
          — every rule, its weight, and what it costs you in false positives.
        </p>
      </section>

      <section aria-labelledby="measured" className="space-y-5">
        <div className="max-w-3xl space-y-2">
          <h2 id="measured" className="text-2xl font-semibold tracking-tight">
            What measuring it changed
          </h2>
          <p className="text-sm text-muted-foreground">
            A scanner that cries wolf gets switched off in week two, so the rules were measured
            against real published code rather than against intuition. Four defects that found, each
            one a false positive on an ordinary package.
          </p>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle className="text-base">
                <span className="font-mono text-sm">Q-CAP-001</span> fired on{' '}
                <span className="font-mono text-sm">regex.exec()</span>
              </CardTitle>
              <CardDescription>
                The rule that reports a package reaching for process execution matched any member
                call ending in <span className="font-mono text-xs">.exec</span> — which is
                <span className="font-mono text-xs"> RegExp.prototype.exec</span>, one of the most
                common calls in JavaScript. Ground truth was computed by an independent AST walk
                over 570 installed packages.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <dl className="flex flex-wrap gap-x-10 gap-y-3">
                <div>
                  <dt className="text-xs tracking-wide text-muted-foreground uppercase">
                    Precision before
                  </dt>
                  <dd className="font-mono text-2xl text-verdict-suspicious-accent tabular-nums">
                    0.312
                  </dd>
                </div>
                <div>
                  <dt className="text-xs tracking-wide text-muted-foreground uppercase">
                    Precision after
                  </dt>
                  <dd className="font-mono text-2xl text-verdict-clean-accent tabular-nums">
                    1.000
                  </dd>
                </div>
                <div>
                  <dt className="text-xs tracking-wide text-muted-foreground uppercase">
                    Recall lost
                  </dt>
                  <dd className="font-mono text-2xl tabular-nums">none</dd>
                </div>
                <div>
                  <dt className="text-xs tracking-wide text-muted-foreground uppercase">
                    False positives removed
                  </dt>
                  <dd className="font-mono text-2xl tabular-nums">60</dd>
                </div>
              </dl>
              <p className="mt-4 text-xs text-muted-foreground">
                69% of that rule&rsquo;s firings were regex matches in{' '}
                <span className="font-mono">picomatch</span>,{' '}
                <span className="font-mono">semver</span>, <span className="font-mono">chalk</span>,{' '}
                <span className="font-mono">eslint</span>, <span className="font-mono">acorn</span>{' '}
                and 55 others. It feeds a hard trigger, so each one was a false &ldquo;do not
                install&rdquo;.
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Every built package looked malicious</CardTitle>
              <CardDescription>
                The rule that catches the <span className="font-mono text-xs">event-stream</span>{' '}
                signature — runnable files in the tarball that the repository does not have — is
                also what a normal build looks like.{' '}
                <span className="font-mono text-xs">lodash</span> scored likely-malicious; so did{' '}
                <span className="font-mono text-xs">esbuild</span> after the first attempt at a fix.
                It now asks whether the repository builds anything before drawing that conclusion.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">The SSRF guard was too blunt</CardTitle>
              <CardDescription>
                Blanket-blocking the NAT64 prefix made GitHub unreachable on any DNS64 network, so
                every provenance check silently returned{' '}
                <span className="font-mono text-xs">PARTIAL</span>. The guard now decodes the IPv4
                address carried inside such an address and applies the ordinary rules — which is
                stricter, not looser, than what it replaced.
              </CardDescription>
            </CardHeader>
          </Card>
        </div>
      </section>

      <section aria-labelledby="verdicts" className="space-y-5">
        <div className="max-w-3xl space-y-2">
          <h2 id="verdicts" className="text-2xl font-semibold tracking-tight">
            A verdict you can argue with
          </h2>
          <p className="text-sm text-muted-foreground">
            Weighted evidence, plus hard triggers for the combinations that have no innocent
            reading. Every verdict ships with the full signal list — fired and not fired — down to
            the file, line and excerpt.
          </p>
        </div>

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {VERDICTS.map((verdict) => (
            <div key={verdict} className="rounded-lg border border-border p-4">
              <VerdictBadge verdict={verdict} appearance="solid" size="md" />
              <p className="mt-3 text-sm text-muted-foreground">
                {VERDICT_META[verdict].description}
              </p>
            </div>
          ))}
        </div>
      </section>

      <section
        aria-labelledby="cta"
        className="rounded-xl border border-border bg-surface/60 p-6 sm:p-10"
      >
        <h2 id="cta" className="text-2xl font-semibold tracking-tight">
          Scan something now
        </h2>
        <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
          Paste a package name or drop in a lockfile. The engine downloads the published artefact,
          extracts it under a hard size and entry budget, reads it statically, and never executes a
          byte of it.
        </p>
        <div className="mt-6 flex flex-wrap gap-3">
          <Button asChild>
            <Link href="/scan">
              <ScanLine aria-hidden="true" />
              Run a scan
            </Link>
          </Button>
          <Button asChild variant="outline">
            <Link href="/research">
              <FileSearch aria-hidden="true" />
              See the evaluation numbers
            </Link>
          </Button>
        </div>
      </section>
    </div>
  );
}
