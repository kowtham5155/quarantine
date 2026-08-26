import { AlertTriangle, FileDiff, GitCompareArrows, ShieldCheck } from 'lucide-react';

import { EmptyState } from '@/components/shared/EmptyState';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { safeText } from '@/lib/safe-display';

import { readVersionParams } from '../../../../params';
import { loadReport } from '../report';

interface PageProps {
  params: Promise<{ eco: string; name: string; version: string }>;
}

const STATUS_COPY: Record<
  string,
  { title: string; detail: string; tone: 'good' | 'bad' | 'unknown' }
> = {
  MATCH: {
    title: 'Tarball matches the repository',
    detail:
      'Every file in the published archive has a counterpart at the resolved tag, and no unexplained file was added.',
    tone: 'good',
  },
  DIVERGENT: {
    title: 'Tarball diverges from the repository',
    detail:
      'The published archive contains code that the repository at this version does not. This is the event-stream signature: code reviewers never saw, shipped to every machine that installs the package.',
    tone: 'bad',
  },
  NO_REPO: {
    title: 'No repository declared',
    detail:
      'The package names no source repository, so there is nothing to compare the artefact against. This is not evidence of wrongdoing — it is the absence of evidence either way.',
    tone: 'unknown',
  },
  REPO_UNREACHABLE: {
    title: 'Repository could not be read',
    detail:
      'The declared repository did not respond, has been deleted, or is private. Conflating "we could not check" with "it does not match" is the biggest false-positive source in provenance analysis, so this is reported as its own state.',
    tone: 'unknown',
  },
  NO_TAG: {
    title: 'No matching tag',
    detail:
      'The repository exists but publishes no tag corresponding to this version, so there is no tree to diff against.',
    tone: 'unknown',
  },
};

function FileList({
  title,
  description,
  files,
  tone,
}: {
  title: string;
  description: string;
  files: string[];
  tone: 'bad' | 'neutral';
}) {
  return (
    <Card
      className={
        tone === 'bad' && files.length > 0 ? 'border-verdict-likely-malicious-accent/40' : ''
      }
    >
      <CardHeader>
        <CardTitle className="text-base">
          {title}
          <span className="ml-2 font-mono text-xs font-normal text-muted-foreground">
            {files.length}
          </span>
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        {files.length === 0 ? (
          <p className="text-sm text-muted-foreground">None.</p>
        ) : (
          <ul className="max-h-72 space-y-1 overflow-y-auto">
            {files.map((file) => (
              <li key={file} className="break-anywhere font-mono text-xs">
                {safeText(file, { maxLength: 240 })}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

export default async function ProvenancePage({ params }: PageProps) {
  const { ecosystem, name, version } = await readVersionParams(params);
  const report = await loadReport(ecosystem, name, version);

  const provenance = report.provenance;

  if (!provenance) {
    return (
      <EmptyState
        icon={GitCompareArrows}
        title="No provenance check was recorded"
        description="This analysis did not complete the provenance family, so there is no tarball-versus-source result to show."
      />
    );
  }

  // A DIVERGENT row that only diverges because the package ships built output
  // is not the event-stream signature and must not be dressed as it. The engine
  // records why it could not conclude; the page reads it back rather than
  // guessing from the file counts.
  const builtOutput = provenance.diffSummary.unverifiable === 'BUILD_OUTPUT';

  const copy = builtOutput
    ? {
        title: 'Published from a build — not directly comparable',
        detail:
          'Most of the runnable files in this archive are absent from the source tree, which is what a built package looks like: the published artefact is generated from the source rather than copied from it. A file-by-file comparison cannot separate ordinary build output from an injected file here, so this check is reported as inconclusive rather than as a match or an accusation. The other five families still read every file in the archive.',
        tone: 'unknown' as const,
      }
    : (STATUS_COPY[provenance.status] ?? STATUS_COPY.NO_REPO);
  const toneClass =
    copy?.tone === 'bad'
      ? 'border-verdict-likely-malicious-accent/40 bg-verdict-likely-malicious-surface text-verdict-likely-malicious-accent'
      : copy?.tone === 'good'
        ? 'border-verdict-clean-accent/40 bg-verdict-clean-surface text-verdict-clean-accent'
        : 'border-verdict-low-risk-accent/40 bg-verdict-low-risk-surface text-verdict-low-risk-accent';

  const Icon = copy?.tone === 'good' ? ShieldCheck : AlertTriangle;

  return (
    <div className="space-y-6">
      <div className={`flex gap-3 rounded-lg border p-4 ${toneClass}`}>
        <Icon aria-hidden="true" className="mt-0.5 size-5 shrink-0" />
        <div className="min-w-0 space-y-1">
          <p className="font-semibold">{copy?.title}</p>
          <p className="text-sm text-muted-foreground">{copy?.detail}</p>
          <p className="font-mono text-xs text-muted-foreground">
            status {provenance.status}
            {provenance.repoUrl
              ? ` · ${safeText(provenance.repoUrl, { maxLength: 120 })}`
              : report.package.repositoryUrl
                ? ` · ${safeText(report.package.repositoryUrl, { maxLength: 120 })}`
                : ''}
            {provenance.gitRef ? ` @ ${safeText(provenance.gitRef, { maxLength: 60 })}` : ''}
          </p>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <FileList
          tone="bad"
          title="Only in the tarball"
          description="Published to every installer, absent from the source tree. The highest-value finding in the system."
          files={provenance.filesOnlyInTarball}
        />
        <FileList
          tone="neutral"
          title="Only in the repository"
          description="Present in source but not shipped. Usually tests, CI config and docs — ordinary packaging."
          files={provenance.filesOnlyInRepo}
        />
        <FileList
          tone="bad"
          title="Modified"
          description="Present in both, with different contents at the resolved tag."
          files={provenance.modifiedFiles}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <FileDiff aria-hidden="true" className="size-4 text-muted-foreground" />
            About this comparison
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <p>
            The comparison runs during analysis: the repository tree at the tag matching this
            version is fetched, normalised, and compared file by file against the extracted tarball.
            What is retained afterwards is the file-level result — which paths were added, removed
            or changed.
          </p>
          <p>
            Line-level diffs are not stored. Keeping a copy of both trees would mean retaining
            package contents, which is exactly what the extraction rules forbid; the file-level
            answer is what a verdict rests on, and it is the part that survives.
          </p>
          {Object.keys(provenance.diffSummary).length > 0 ? (
            <dl className="flex flex-wrap gap-x-6 gap-y-1 font-mono text-xs">
              {Object.entries(provenance.diffSummary).map(([key, value]) => (
                <div key={key} className="flex gap-1.5">
                  <dt>{safeText(key, { maxLength: 40 })}</dt>
                  <dd className="text-foreground">{safeText(String(value), { maxLength: 40 })}</dd>
                </div>
              ))}
            </dl>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
