import type { Metadata } from 'next';
import Link from 'next/link';
import {
  Activity,
  Boxes,
  Gauge,
  PackageSearch,
  Radar,
  ShieldAlert,
  ShieldX,
  Siren,
  Timer,
} from 'lucide-react';

import { EmptyState } from '@/components/shared/EmptyState';
import { PackageRef } from '@/components/shared/PackageRef';
import { PageHeader } from '@/components/shared/PageHeader';
import { SignalBadge } from '@/components/shared/SignalBadge';
import { StatCard } from '@/components/shared/StatCard';
import { TimeAgo } from '@/components/shared/TimeAgo';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { VerdictDistribution } from '@/components/shared/VerdictDistribution';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { requireAuthContext } from '@/lib/auth-context';
import { SIGNAL_FAMILY_META } from '@/lib/constants';
import { ecosystemSlug, versionHref } from '@/lib/routes';
import { getDashboardSummary, THROUGHPUT_DAYS } from '@/lib/services/dashboard.service';

import { ThroughputChart } from './ThroughputChart';

export const metadata: Metadata = { title: 'Dashboard' };

function formatDuration(ms: number | null): string {
  if (ms === null) return '—';
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}

export default async function DashboardPage() {
  const ctx = await requireAuthContext();
  const summary = await getDashboardSummary(ctx);

  const familyTotal = summary.familyTotals.reduce((total, row) => total + row.count, 0);

  return (
    <div className="space-y-8">
      <PageHeader
        title="Dashboard"
        description="Everything this organisation has analysed, and what needs a decision."
        actions={
          <Button asChild>
            <Link href="/scan">
              <Radar aria-hidden="true" />
              New scan
            </Link>
          </Button>
        }
      />

      <section aria-labelledby="posture" className="space-y-4">
        <h2 id="posture" className="sr-only">
          Posture
        </h2>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
          <StatCard
            label="Packages"
            value={summary.packagesAnalysed}
            hint={`${summary.versionsAnalysed} versions analysed`}
            icon={PackageSearch}
          />
          <StatCard
            label="Malicious"
            value={summary.maliciousCount}
            hint="likely or known malicious"
            icon={ShieldX}
          />
          <StatCard
            label="Suspicious"
            value={summary.suspiciousCount}
            hint="corroborated across families"
            icon={ShieldAlert}
          />
          <StatCard
            label="Open violations"
            value={summary.openViolations}
            hint="policy decisions pending"
            icon={Siren}
          />
          <StatCard
            label="Quarantine"
            value={summary.quarantineDepth}
            hint="held for review"
            icon={Boxes}
          />
          <StatCard
            label="Queue"
            value={summary.queueDepth}
            hint={`p95 ${formatDuration(summary.p95DurationMs)}`}
            icon={Timer}
          />
        </div>
      </section>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Analysis throughput</CardTitle>
            <CardDescription>
              Completed analyses per day over the last {THROUGHPUT_DAYS} days, and how many of them
              came back flagged.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {summary.throughput.some((point) => point.completed > 0) ? (
              <ThroughputChart points={summary.throughput} />
            ) : (
              <EmptyState
                size="sm"
                icon={Activity}
                title="Nothing has completed in this window"
                description={`No analysis finished in the last ${THROUGHPUT_DAYS} days.`}
                action={
                  <Button asChild size="sm">
                    <Link href="/scan">Run a scan</Link>
                  </Button>
                }
              />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Verdict distribution</CardTitle>
            <CardDescription>
              Across all {summary.analysesTotal} analyses this organisation has run.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <VerdictDistribution slices={summary.verdictDistribution} />
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Recent analyses</CardTitle>
            <CardDescription>The last eight, newest first.</CardDescription>
          </CardHeader>
          <CardContent>
            {summary.recentAnalyses.length === 0 ? (
              <EmptyState
                size="sm"
                icon={PackageSearch}
                title="No analyses yet"
                description="Scan a package to see it here."
                action={
                  <Button asChild size="sm">
                    <Link href="/scan">Scan a package</Link>
                  </Button>
                }
              />
            ) : (
              <ul className="divide-y divide-border">
                {summary.recentAnalyses.map((analysis) => (
                  <li
                    key={analysis.id}
                    className="flex flex-wrap items-center gap-3 py-3 first:pt-0 last:pb-0"
                  >
                    <PackageRef
                      name={analysis.name}
                      version={analysis.version}
                      ecosystem={ecosystemSlug(analysis.ecosystem)}
                      href={versionHref(analysis.ecosystem, analysis.name, analysis.version)}
                      className="min-w-0 flex-1"
                    />
                    {analysis.verdict ? (
                      <VerdictBadge verdict={analysis.verdict} size="sm" />
                    ) : (
                      <Badge variant="secondary" className="text-xs">
                        {analysis.status}
                      </Badge>
                    )}
                    <TimeAgo
                      date={analysis.completedAt ?? analysis.createdAt}
                      className="w-24 shrink-0 text-right text-xs text-muted-foreground"
                    />
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Signals by family</CardTitle>
              <CardDescription>
                {familyTotal} hits recorded across {summary.analysesTotal} analyses.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {familyTotal === 0 ? (
                <p className="py-2 text-sm text-muted-foreground">No signal has fired yet.</p>
              ) : (
                <ul className="space-y-2.5">
                  {[...summary.familyTotals]
                    .sort((a, b) => b.count - a.count)
                    .map((row) => {
                      const share = Math.round((row.count / familyTotal) * 100);
                      return (
                        <li key={row.family} className="space-y-1.5">
                          <div className="flex items-center justify-between gap-2">
                            <SignalBadge family={row.family} />
                            <span className="font-mono text-xs text-muted-foreground tabular-nums">
                              {row.count}
                            </span>
                          </div>
                          <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
                            <div
                              className="h-full rounded-full"
                              style={{
                                width: `${share}%`,
                                backgroundColor: SIGNAL_FAMILY_META[row.family].hex,
                              }}
                            />
                          </div>
                        </li>
                      );
                    })}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Recent campaigns</CardTitle>
              <CardDescription>Clusters sharing an indicator.</CardDescription>
            </CardHeader>
            <CardContent>
              {summary.recentCampaigns.length === 0 ? (
                <p className="py-2 text-sm text-muted-foreground">
                  No campaign has formed yet. Clusters appear once two analyses share an
                  exfiltration endpoint, a maintainer or a payload hash.
                </p>
              ) : (
                <ul className="space-y-3">
                  {summary.recentCampaigns.map((campaign) => (
                    <li key={campaign.id} className="space-y-1">
                      <p className="break-anywhere text-sm font-medium">{campaign.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {campaign.packageCount} packages · last seen{' '}
                        <TimeAgo date={campaign.lastSeenAt} />
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      <p className="flex items-center gap-2 text-xs text-muted-foreground">
        <Gauge aria-hidden="true" className="size-3.5" />
        Mean analysis time {formatDuration(summary.meanDurationMs)} over the last {THROUGHPUT_DAYS}{' '}
        days.
      </p>
    </div>
  );
}
