import type { Metadata } from 'next';
import Link from 'next/link';
import { FileWarning, Lock, ServerCog, ShieldAlert } from 'lucide-react';

import { PageHeader } from '@/components/shared/PageHeader';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

export const metadata: Metadata = {
  title: 'Security',
  description:
    'Quarantine downloads untrusted archives that may contain real malware. This is our own threat model and the controls that follow from it.',
};

const CONTROLS = [
  {
    icon: ShieldAlert,
    title: 'Package contents are never executed',
    body: 'Nothing in an analysed package is executed, required, imported or evaluated — not by the engine, not by a test, not by a build step. `npm install` is never run on an analysed package. Analysis is parsing with @babel/parser, walking the AST, and reading bytes.',
  },
  {
    icon: FileWarning,
    title: 'Extraction is bounded and path-checked',
    body: 'A tarball is capped at 50MB total, 10,000 entries, 10MB per file and depth 20. Every entry path is resolved against the extraction root and rejected if it escapes — the zip-slip guard. Extraction goes to a per-scan temp directory that is deleted in a finally block on every exit path.',
  },
  {
    icon: ServerCog,
    title: 'Outbound requests are SSRF-guarded',
    body: 'All network calls go through one client: DNS resolved before connecting, private and link-local ranges rejected (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, ::1, fc00::/7), 10-second timeout, at most three redirects, a fixed User-Agent and per-host rate limiting.',
  },
  {
    icon: Lock,
    title: 'Package strings are treated as hostile on render',
    body: 'Names, versions, file paths, excerpts and maintainer handles are attacker-controlled. They are escaped as text, never injected as HTML, and bidirectional and zero-width characters are stripped so a Trojan Source payload cannot reorder what an analyst reads. No syntax highlighter runs over package source, because every highlighter works by producing HTML.',
  },
] as const;

export default function SecurityPage() {
  return (
    <div className="space-y-12">
      <PageHeader
        title="Our own threat model"
        description="This is a security tool that handles malware samples. Its own threat model is part of the design, not an afterthought — and publishing it is the only honest way to ask anyone to trust it."
      />

      <section
        aria-labelledby="premise"
        className="max-w-3xl space-y-3 text-sm text-muted-foreground"
      >
        <h2 id="premise" className="text-2xl font-semibold tracking-tight text-foreground">
          The premise
        </h2>
        <p>
          To answer &ldquo;is this package malicious?&rdquo;, Quarantine downloads the actual published
          artefact. That means this system deliberately fetches and stores, however briefly, files
          that are sometimes real malware. Every control below exists because of that one fact.
        </p>
        <p>
          The failure mode we design against is not &ldquo;an analysis returns the wrong verdict&rdquo;. It is
          &ldquo;an analysis executes the sample&rdquo;.
        </p>
      </section>

      <section aria-labelledby="controls" className="space-y-4">
        <h2 id="controls" className="text-2xl font-semibold tracking-tight">
          Controls
        </h2>
        <div className="grid gap-4 lg:grid-cols-2">
          {CONTROLS.map((control) => {
            const Icon = control.icon;
            return (
              <Card key={control.title} className="h-full">
                <CardHeader>
                  <CardTitle className="flex items-start gap-2 text-base">
                    <Icon aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-primary" />
                    {control.title}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground">{control.body}</p>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </section>

      <section aria-labelledby="platform" className="space-y-4">
        <h2 id="platform" className="text-2xl font-semibold tracking-tight">
          Platform security
        </h2>
        <div className="grid gap-4 sm:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Accounts and sessions</CardTitle>
              <CardDescription>What protects an organisation&apos;s findings.</CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="list-disc space-y-1.5 pl-5 text-sm text-muted-foreground">
                <li>Argon2id password hashing, 12-character minimum with a strength floor</li>
                <li>Optional TOTP second factor with single-use recovery codes</li>
                <li>
                  HttpOnly, Secure, SameSite cookies; 30-minute idle and 12-hour absolute caps
                </li>
                <li>Login rate limiting per IP and email, then exponential lockout</li>
                <li>Append-only audit log for every privileged action</li>
              </ul>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Transport and isolation</CardTitle>
              <CardDescription>What protects one tenant from another.</CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="list-disc space-y-1.5 pl-5 text-sm text-muted-foreground">
                <li>Strict CSP with a per-request nonce; no unsafe-inline scripts</li>
                <li>HSTS, X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy</li>
                <li>Every tenant query filtered on the organisation in the service layer</li>
                <li>
                  Authorisation checked against the database on every call, never in the browser
                </li>
                <li>Parameterised queries only; no raw SQL interpolation</li>
              </ul>
            </CardContent>
          </Card>
        </div>
      </section>

      <section aria-labelledby="disclosure" className="max-w-3xl space-y-3">
        <h2 id="disclosure" className="text-2xl font-semibold tracking-tight">
          Reporting a problem
        </h2>
        <p className="text-sm text-muted-foreground">
          If you find a way to make this system execute package content, escape the extraction root,
          reach a private network address through the fetcher, or read another organisation&apos;s
          analyses, that is the class of bug we most want to hear about. Report it privately through
          the repository&apos;s security advisory form rather than opening a public issue.
        </p>
        <p className="text-sm text-muted-foreground">
          The detection methodology is documented on{' '}
          <Link href="/how-it-works" className="text-primary underline-offset-4 hover:underline">
            how it works
          </Link>
          , and every rule is published on the{' '}
          <Link href="/detections" className="text-primary underline-offset-4 hover:underline">
            detection catalogue
          </Link>
          .
        </p>
      </section>
    </div>
  );
}
