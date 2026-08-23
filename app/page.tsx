import Link from 'next/link';
import { ArrowRight, PackageSearch, ShieldCheck, TerminalSquare } from 'lucide-react';

import { SignalBadge } from '@/components/shared/SignalBadge';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { SIGNAL_FAMILIES, SIGNAL_FAMILY_META, VERDICTS } from '@/lib/constants';

export default function HomePage() {
  return (
    <div className="flex min-h-svh flex-col">
      <header className="sticky top-0 z-40 border-b border-border backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center gap-3 px-4 sm:px-6">
          <Link href="/" className="flex items-center gap-2 font-semibold tracking-tight">
            <ShieldCheck aria-hidden="true" className="size-5 text-primary" />
            Quarantine
          </Link>
          <nav
            aria-label="Primary"
            className="ml-6 hidden gap-5 text-sm text-muted-foreground md:flex"
          >
            <Link href="/how-it-works" className="hover:text-foreground">
              How it works
            </Link>
            <Link href="/detections" className="hover:text-foreground">
              Detections
            </Link>
            <Link href="/research" className="hover:text-foreground">
              Research
            </Link>
            <Link href="/docs" className="hover:text-foreground">
              Docs
            </Link>
          </nav>
          <div className="ml-auto flex items-center gap-2">
            <Button asChild variant="ghost" size="sm">
              <Link href="/login">Sign in</Link>
            </Button>
            <Button asChild size="sm">
              <Link href="/scan">Scan a package</Link>
            </Button>
          </div>
        </div>
      </header>

      <main id="main" className="mx-auto w-full max-w-6xl flex-1 px-4 py-16 sm:px-6 sm:py-24">
        <section className="max-w-3xl">
          <p className="mb-3 font-mono text-xs tracking-widest text-primary uppercase">
            Pre-install supply chain malware detection
          </p>
          <h1 className="text-3xl font-semibold tracking-tight text-balance sm:text-5xl">
            <code className="font-mono">npm audit</code> tells you about known vulnerabilities in
            code that is already on your machine.
          </h1>
          <p className="mt-5 max-w-2xl text-base text-muted-foreground sm:text-lg">
            Quarantine analyses the actual published tarball — not a CVE database — and returns a
            verdict <em>before</em> a package reaches a developer machine or a CI runner. Six
            independent signal families, roughly forty rules, purely static analysis.
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

        <section aria-labelledby="verdicts" className="mt-20">
          <h2 id="verdicts" className="text-sm font-semibold tracking-wide uppercase">
            The verdict scale
          </h2>
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
            Every analysis lands on one of five verdicts, always paired with a confidence figure
            derived from how much of the package the engine could actually inspect.
          </p>
          <div className="mt-5 flex flex-wrap gap-2">
            {VERDICTS.map((verdict) => (
              <VerdictBadge key={verdict} verdict={verdict} appearance="solid" size="lg" />
            ))}
          </div>
        </section>

        <section aria-labelledby="families" className="mt-16">
          <h2 id="families" className="text-sm font-semibold tracking-wide uppercase">
            Six signal families
          </h2>
          <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {SIGNAL_FAMILIES.map((family) => {
              const meta = SIGNAL_FAMILY_META[family];
              return (
                <Card key={family}>
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
        </section>
      </main>

      <footer className="border-t border-border">
        <div className="mx-auto flex max-w-6xl flex-col gap-2 px-4 py-6 text-xs text-muted-foreground sm:flex-row sm:items-center sm:px-6">
          <p>Static analysis only. Package contents are never executed.</p>
          <nav aria-label="Footer" className="flex gap-4 sm:ml-auto">
            <Link href="/security" className="hover:text-foreground">
              Security
            </Link>
            <Link href="/legal/terms" className="hover:text-foreground">
              Terms
            </Link>
            <Link href="/legal/privacy" className="hover:text-foreground">
              Privacy
            </Link>
          </nav>
        </div>
      </footer>
    </div>
  );
}
