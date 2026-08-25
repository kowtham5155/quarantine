import { CircleUser, PackagePlus, UserMinus, UserPlus } from 'lucide-react';

import { EmptyState } from '@/components/shared/EmptyState';
import { SignalBadge } from '@/components/shared/SignalBadge';
import { TimeAgo } from '@/components/shared/TimeAgo';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { requireAuthContext } from '@/lib/auth-context';
import { DORMANCY_DAYS, DORMANCY_SEVERE_DAYS } from '@/lib/engine/thresholds';
import { safeText } from '@/lib/safe-display';
import { getPackageOverview } from '@/lib/services/package.service';

import { readVersionParams } from '../../../../params';
import { loadReport } from '../report';

interface PageProps {
  params: Promise<{ eco: string; name: string; version: string }>;
}

const DAY_MS = 24 * 60 * 60 * 1000;

interface TimelineEntry {
  key: string;
  kind: 'release' | 'maintainer';
  at: Date;
  label: string;
  detail?: string;
  eventType?: 'ADDED' | 'REMOVED' | 'PUBLISHED';
  /** Days since the previous release, when this entry is a release. */
  gapDays?: number;
  isCurrent?: boolean;
}

export default async function MaintainersPage({ params }: PageProps) {
  const ctx = await requireAuthContext();
  const { ecosystem, name, version } = await readVersionParams(params);
  const [report, pkg] = await Promise.all([
    loadReport(ecosystem, name, version),
    getPackageOverview(ctx, ecosystem, name),
  ]);

  const releases = pkg.versions
    .filter((row): row is typeof row & { publishedAt: Date } => row.publishedAt !== null)
    .sort((a, b) => a.publishedAt.getTime() - b.publishedAt.getTime());

  const entries: TimelineEntry[] = [];

  releases.forEach((release, index) => {
    const previous = index > 0 ? releases[index - 1] : undefined;
    const gapDays = previous
      ? Math.round((release.publishedAt.getTime() - previous.publishedAt.getTime()) / DAY_MS)
      : undefined;

    entries.push({
      key: `release-${release.id}`,
      kind: 'release',
      at: release.publishedAt,
      label: safeText(release.version, { maxLength: 40 }),
      ...(gapDays === undefined ? {} : { gapDays }),
      isCurrent: release.version === version,
      ...(release.latest?.verdict ? { detail: release.latest.verdict } : {}),
    });
  });

  for (const event of pkg.maintainerEvents) {
    entries.push({
      key: `event-${event.id}`,
      kind: 'maintainer',
      at: event.occurredAt,
      label: safeText(event.actor, { maxLength: 80 }),
      eventType: event.type,
    });
  }

  entries.sort((a, b) => b.at.getTime() - a.at.getTime());

  const maintainerHits = report.hits.filter((hit) => hit.family === 'MAINTAINER');
  const maintainerRules = new Map(
    report.rules.filter((rule) => rule.family === 'MAINTAINER').map((rule) => [rule.ruleId, rule]),
  );
  const firedMaintainerRules = [...new Set(maintainerHits.map((hit) => hit.ruleId))];

  return (
    <div className="space-y-6">
      <div className="max-w-3xl space-y-1">
        <h2 className="text-lg font-semibold tracking-tight">Release and maintainer forensics</h2>
        <p className="text-sm text-muted-foreground">
          A gap of {DORMANCY_DAYS} days or more before a release is marked as a dormancy break, and{' '}
          {DORMANCY_SEVERE_DAYS} days or more as a severe one. A maintainer added shortly before a
          release is the pattern behind most account-takeover incidents.
        </p>
      </div>

      {firedMaintainerRules.length > 0 ? (
        <Card className="border-verdict-suspicious-accent/40">
          <CardHeader>
            <CardTitle className="text-base">What fired in this family</CardTitle>
            <CardDescription>
              {firedMaintainerRules.length} of{' '}
              {report.families.find((family) => family.family === 'MAINTAINER')?.evaluated ?? 0}{' '}
              maintainer rules matched.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {firedMaintainerRules.map((ruleId) => {
                const rule = maintainerRules.get(ruleId);
                return (
                  <li key={ruleId} className="flex flex-wrap items-center gap-2 text-sm">
                    <SignalBadge family="MAINTAINER" ruleId={ruleId} compact />
                    <span className="font-medium">{rule?.name ?? ruleId}</span>
                    <span className="text-muted-foreground">{rule?.description}</span>
                  </li>
                );
              })}
            </ul>
          </CardContent>
        </Card>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-[1fr_18rem]">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Timeline</CardTitle>
            <CardDescription>Releases and maintainer changes, newest first.</CardDescription>
          </CardHeader>
          <CardContent>
            {entries.length === 0 ? (
              <EmptyState
                size="sm"
                title="No release history recorded"
                description="The registry returned no publish timestamps for this package."
              />
            ) : (
              <ol className="space-y-3">
                {entries.map((entry) => {
                  const dormant = (entry.gapDays ?? 0) >= DORMANCY_DAYS;
                  const severe = (entry.gapDays ?? 0) >= DORMANCY_SEVERE_DAYS;

                  const Icon =
                    entry.kind === 'release'
                      ? PackagePlus
                      : entry.eventType === 'REMOVED'
                        ? UserMinus
                        : entry.eventType === 'ADDED'
                          ? UserPlus
                          : CircleUser;

                  return (
                    <li
                      key={entry.key}
                      className={`flex gap-3 rounded-md border p-3 ${
                        entry.isCurrent
                          ? 'border-primary/50 bg-primary/5'
                          : severe
                            ? 'border-verdict-suspicious-accent/40'
                            : 'border-border'
                      }`}
                    >
                      <Icon
                        aria-hidden="true"
                        className="mt-0.5 size-4 shrink-0 text-muted-foreground"
                      />
                      <div className="min-w-0 flex-1 space-y-1">
                        <p className="flex flex-wrap items-center gap-2 text-sm">
                          <span className="break-anywhere font-mono">{entry.label}</span>
                          {entry.kind === 'maintainer' && entry.eventType ? (
                            <Badge variant="secondary" className="text-[10px]">
                              {entry.eventType}
                            </Badge>
                          ) : null}
                          {entry.isCurrent ? (
                            <Badge className="text-[10px]">This version</Badge>
                          ) : null}
                          {dormant ? (
                            <span className="text-xs text-verdict-suspicious-accent">
                              {severe ? 'Severe dormancy break' : 'Dormancy break'} —{' '}
                              {entry.gapDays} days since the previous release
                            </span>
                          ) : null}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          <TimeAgo date={entry.at} />
                          {entry.detail ? ` · ${entry.detail}` : ''}
                        </p>
                      </div>
                    </li>
                  );
                })}
              </ol>
            )}
          </CardContent>
        </Card>

        <Card className="h-fit">
          <CardHeader>
            <CardTitle className="text-base">Maintainers</CardTitle>
            <CardDescription>
              {pkg.maintainerCount === 1
                ? 'A sole maintainer is a takeover exposure on a popular package.'
                : 'Accounts seen on this package.'}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {pkg.maintainers.length === 0 ? (
              <p className="text-sm text-muted-foreground">No maintainer recorded.</p>
            ) : (
              <ul className="space-y-1.5">
                {pkg.maintainers.map((maintainer) => (
                  <li key={maintainer} className="break-anywhere font-mono text-xs">
                    {safeText(maintainer, { maxLength: 80 })}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
