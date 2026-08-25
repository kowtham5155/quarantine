import type { Metadata } from 'next';
import Link from 'next/link';
import { AlertTriangle, ExternalLink, GitBranch, Radar, Users } from 'lucide-react';

import { EmptyState } from '@/components/shared/EmptyState';
import { PageHeader } from '@/components/shared/PageHeader';
import { StatCard } from '@/components/shared/StatCard';
import { TimeAgo } from '@/components/shared/TimeAgo';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Badge } from '@/components/ui/badge';
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
import { requireAuthContext } from '@/lib/auth-context';
import { ecosystemSlug, similarHref, versionHref } from '@/lib/routes';
import { safeText } from '@/lib/safe-display';
import { getPackageOverview } from '@/lib/services/package.service';

import { readPackageParams } from '../../params';

interface PageProps {
  params: Promise<{ eco: string; name: string }>;
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const { name } = await readPackageParams(params);
  return { title: safeText(name, { maxLength: 120 }) };
}

function formatBytes(bytes: number | null): string {
  if (bytes === null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} kB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default async function PackageOverviewPage({ params }: PageProps) {
  const ctx = await requireAuthContext();
  const { ecosystem, name } = await readPackageParams(params);
  const pkg = await getPackageOverview(ctx, ecosystem, name);

  const analysed = pkg.versions.filter((version) => version.latest !== null);
  const slug = ecosystemSlug(pkg.ecosystem);

  return (
    <div className="space-y-8">
      <PageHeader
        breadcrumbs={[
          { label: 'Packages', href: '/packages' },
          { label: safeText(pkg.name, { maxLength: 60 }) },
        ]}
        title={<span className="break-anywhere font-mono">{safeText(pkg.name)}</span>}
        description={pkg.description ? safeText(pkg.description, { maxLength: 300 }) : undefined}
        meta={
          <>
            <span className="rounded border border-border px-1.5 py-px font-mono text-[10px] text-muted-foreground uppercase">
              {slug}
            </span>
            {pkg.worstVerdict ? <VerdictBadge verdict={pkg.worstVerdict} size="sm" /> : null}
            {pkg.isDeprecated ? (
              <Badge variant="secondary" className="text-xs">
                Deprecated
              </Badge>
            ) : null}
            {pkg.repositoryUrl ? (
              <span className="inline-flex items-center gap-1 font-mono text-xs text-muted-foreground">
                <GitBranch aria-hidden="true" className="size-3.5" />
                {safeText(pkg.repositoryUrl, { maxLength: 80 })}
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-xs text-verdict-low-risk-accent">
                <AlertTriangle aria-hidden="true" className="size-3.5" />
                No repository declared
              </span>
            )}
          </>
        }
        actions={
          <>
            <Button asChild variant="outline">
              <Link href={similarHref(pkg.ecosystem, pkg.name)}>Typosquat neighbourhood</Link>
            </Button>
            <Button asChild>
              <Link href="/scan">
                <Radar aria-hidden="true" />
                Scan a version
              </Link>
            </Button>
          </>
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Weekly downloads"
          value={pkg.weeklyDownloads.toLocaleString('en-GB')}
          hint="as reported by the registry"
        />
        <StatCard
          label="Versions analysed"
          value={analysed.length}
          hint={`${pkg.versions.length} known here`}
        />
        <StatCard
          label="Maintainers"
          value={pkg.maintainerCount || pkg.maintainers.length}
          hint={pkg.maintainerCount === 1 ? 'sole maintainer' : 'on the current release'}
          icon={Users}
        />
        <StatCard
          label="First published"
          value={pkg.firstPublishedAt ? pkg.firstPublishedAt.toISOString().slice(0, 10) : '—'}
          hint="registry record"
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Versions</CardTitle>
          <CardDescription>
            Verdicts are this organisation&apos;s own. A version with no verdict has not been
            analysed here.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {pkg.versions.length === 0 ? (
            <EmptyState
              size="sm"
              title="No versions recorded"
              description="Scan this package to populate its version history."
            />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Version</TableHead>
                    <TableHead>Published</TableHead>
                    <TableHead>Verdict</TableHead>
                    <TableHead className="text-right">Score</TableHead>
                    <TableHead className="text-right">Files</TableHead>
                    <TableHead className="text-right">Size</TableHead>
                    <TableHead>Install scripts</TableHead>
                    <TableHead className="text-right">Report</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pkg.versions.map((version) => (
                    <TableRow key={version.id}>
                      <TableCell className="font-mono text-xs">
                        {safeText(version.version, { maxLength: 40 })}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {version.publishedAt ? <TimeAgo date={version.publishedAt} /> : '—'}
                      </TableCell>
                      <TableCell>
                        {version.latest?.verdict ? (
                          <VerdictBadge verdict={version.latest.verdict} size="sm" />
                        ) : version.latest ? (
                          <Badge variant="secondary" className="text-xs">
                            {version.latest.status}
                          </Badge>
                        ) : (
                          <span className="text-xs text-muted-foreground">Not analysed</span>
                        )}
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">
                        {version.latest?.weightedScore === null ||
                        version.latest?.weightedScore === undefined
                          ? '—'
                          : version.latest.weightedScore.toFixed(1)}
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">
                        {version.fileCount ?? '—'}
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">
                        {formatBytes(version.unpackedSize)}
                      </TableCell>
                      <TableCell>
                        {version.hasInstallScripts ? (
                          <span className="text-xs text-verdict-suspicious-accent">Yes</span>
                        ) : (
                          <span className="text-xs text-muted-foreground">No</span>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        {version.latest ? (
                          <Link
                            href={versionHref(pkg.ecosystem, pkg.name, version.version)}
                            className="text-xs text-primary underline-offset-4 hover:underline"
                          >
                            Open
                          </Link>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Maintainers</CardTitle>
            <CardDescription>Accounts seen publishing or added to this package.</CardDescription>
          </CardHeader>
          <CardContent>
            {pkg.maintainers.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No maintainer history has been recorded for this package.
              </p>
            ) : (
              <ul className="flex flex-wrap gap-2">
                {pkg.maintainers.map((maintainer) => (
                  <li
                    key={maintainer}
                    className="break-anywhere rounded-md border border-border px-2 py-1 font-mono text-xs"
                  >
                    {safeText(maintainer, { maxLength: 60 })}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Recent maintainer events</CardTitle>
            <CardDescription>
              A maintainer added shortly before a release is one of the strongest forensic signals.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {pkg.maintainerEvents.length === 0 ? (
              <p className="text-sm text-muted-foreground">No events recorded.</p>
            ) : (
              <ul className="space-y-2">
                {pkg.maintainerEvents.slice(0, 8).map((event) => (
                  <li key={event.id} className="flex items-center gap-2 text-sm">
                    <Badge
                      variant={event.type === 'ADDED' ? 'default' : 'secondary'}
                      className="text-[10px]"
                    >
                      {event.type}
                    </Badge>
                    <span className="break-anywhere min-w-0 font-mono text-xs">
                      {safeText(event.actor, { maxLength: 60 })}
                    </span>
                    <TimeAgo
                      date={event.occurredAt}
                      className="ml-auto shrink-0 text-xs text-muted-foreground"
                    />
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      {pkg.repositoryUrl ? (
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <ExternalLink aria-hidden="true" className="size-3.5" />
          Repository URL as declared by the package:{' '}
          <span className="break-anywhere font-mono">{safeText(pkg.repositoryUrl)}</span> — shown as
          text, never as a link, because it is attacker-controlled.
        </p>
      ) : null}
    </div>
  );
}
