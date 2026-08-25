import type { Metadata } from 'next';

import { PageHeader } from '@/components/shared/PageHeader';

export const metadata: Metadata = {
  title: 'Terms',
  description: 'Terms of use for Quarantine.',
};

const SECTIONS = [
  {
    heading: 'What this service does',
    body: 'Quarantine downloads published open-source package artefacts and analyses them statically, returning a verdict, a confidence figure and the evidence behind both. It is a decision-support tool. It does not remove, patch or block anything on your systems.',
  },
  {
    heading: 'No warranty on verdicts',
    body: 'A CLEAN verdict is not a guarantee that a package is safe, and a malicious verdict is not proof of intent. The engine reports what it observed in the artefact it downloaded, with a stated confidence, and publishes its own false-positive rate precisely so that you can weigh it. Treat a verdict as evidence, not as a ruling.',
  },
  {
    heading: 'Acceptable use',
    body: 'Do not use the service to attack the package registries it reads from, to scan at a rate intended to exhaust shared capacity, or to host or distribute malware samples. Rate limits apply per organisation and per user, and abuse of them is grounds for suspension.',
  },
  {
    heading: 'Your content',
    body: 'Lockfiles, project names and organisation data you upload remain yours. Package artefacts fetched from a public registry are not yours or ours — they are public artefacts, analysed and then deleted.',
  },
  {
    heading: 'Availability',
    body: 'The service is provided as-is, with no uptime commitment. Analyses depend on third-party registries and code hosts that can be slow, rate-limited or unavailable; when that happens an analysis is reported as partial rather than silently completed.',
  },
  {
    heading: 'Changes',
    body: 'Detection rules, weights and thresholds change as the engine is tuned against the evaluation corpus. A verdict is a statement about a package at a point in time under a stated engine version, which is recorded on every analysis.',
  },
] as const;

export default function TermsPage() {
  return (
    <div className="space-y-10">
      <PageHeader
        title="Terms of use"
        description="Plain-language terms. Nothing here is a substitute for legal advice, and this deployment is a portfolio project rather than a commercial service."
      />

      <div className="max-w-3xl space-y-8">
        {SECTIONS.map((section) => (
          <section key={section.heading} className="space-y-2">
            <h2 className="text-lg font-semibold tracking-tight">{section.heading}</h2>
            <p className="text-sm text-muted-foreground">{section.body}</p>
          </section>
        ))}
      </div>
    </div>
  );
}
