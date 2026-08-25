import type { Metadata } from 'next';
import Link from 'next/link';

import { PageHeader } from '@/components/shared/PageHeader';

export const metadata: Metadata = {
  title: 'Privacy',
  description: 'What Quarantine stores, what it does not store, and for how long.',
};

const KEPT = [
  ['Account', 'Email address, display name, hashed password, TOTP secret when enabled.'],
  [
    'Sessions',
    'A hashed session token, IP address and user agent, so you can revoke a session you do not recognise.',
  ],
  ['Organisations', 'Name, slug, plan, membership and role for each member.'],
  [
    'Analyses',
    'The package coordinate analysed, the verdict, the score, and the evidence: rule id, file path, line range and a short excerpt of the matching source.',
  ],
  [
    'Audit log',
    'Append-only records of privileged actions: who did what, when, from which address.',
  ],
] as const;

const NOT_KEPT = [
  'Package contents. The tarball is extracted into a per-scan temporary directory and deleted before the analysis returns. What survives is the evidence — paths, line numbers and short excerpts — not the archive.',
  'Plaintext passwords, ever. Passwords are hashed with Argon2id and never logged.',
  'Plaintext API keys. Only a SHA-256 digest is stored; the key itself is shown exactly once, at creation.',
  'Third-party analytics or advertising trackers. There are none on this site.',
] as const;

export default function PrivacyPage() {
  return (
    <div className="space-y-10">
      <PageHeader
        title="Privacy"
        description="What is stored, what is deliberately not stored, and why. This deployment is a portfolio project — treat it accordingly with real secrets."
      />

      <section className="max-w-3xl space-y-4">
        <h2 className="text-lg font-semibold tracking-tight">What is stored</h2>
        <dl className="space-y-3">
          {KEPT.map(([term, detail]) => (
            <div key={term} className="rounded-lg border border-border p-4">
              <dt className="text-sm font-semibold">{term}</dt>
              <dd className="mt-1 text-sm text-muted-foreground">{detail}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section className="max-w-3xl space-y-3">
        <h2 className="text-lg font-semibold tracking-tight">What is not stored</h2>
        <ul className="list-disc space-y-2 pl-5 text-sm text-muted-foreground">
          {NOT_KEPT.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>

      <section className="max-w-3xl space-y-3">
        <h2 className="text-lg font-semibold tracking-tight">Logs</h2>
        <p className="text-sm text-muted-foreground">
          Server logs carry a request-scoped correlation id and are redacted: no passwords, tokens,
          cookies or API keys reach them. Package-derived strings that do appear are treated as
          data, never interpolated into anything executable.
        </p>
      </section>

      <section className="max-w-3xl space-y-3">
        <h2 className="text-lg font-semibold tracking-tight">Deletion</h2>
        <p className="text-sm text-muted-foreground">
          Deleting an organisation removes its analyses, projects, policies and alerts. The
          append-only audit log is retained for the organisation&apos;s own accountability and is handled
          out of band. Details of how sample handling works are on the{' '}
          <Link href="/security" className="text-primary underline-offset-4 hover:underline">
            security page
          </Link>
          .
        </p>
      </section>
    </div>
  );
}
