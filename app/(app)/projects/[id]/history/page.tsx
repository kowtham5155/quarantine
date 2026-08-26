import type { Metadata } from 'next';
import { History } from 'lucide-react';

import { EmptyState } from '@/components/shared/EmptyState';
import { TimeAgo } from '@/components/shared/TimeAgo';
import { Badge } from '@/components/ui/badge';
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
import * as projectService from '@/lib/services/project.service';

import { readProjectId } from '../project';
import { RiskHistoryChart, type RiskHistoryPoint } from './RiskHistoryChart';

export const metadata: Metadata = { title: 'History' };

interface PageProps {
  params: Promise<{ id: string }>;
}

const STATUS_VARIANT = {
  COMPLETED: 'secondary',
  RUNNING: 'outline',
  QUEUED: 'outline',
  FAILED: 'destructive',
} as const;

/** Signed change against the previous import, or nothing for the first one. */
function Delta({ current, previous }: { current: number; previous: number | null }) {
  if (previous === null || current === previous) {
    return <span className="text-xs text-muted-foreground">—</span>;
  }

  const change = current - previous;
  return (
    <span className="font-mono text-xs text-muted-foreground tabular-nums">
      {change > 0 ? '+' : ''}
      {change}
    </span>
  );
}

export default async function ProjectHistoryPage({ params }: PageProps) {
  const projectId = await readProjectId(params);
  const ctx = await requireAuthContext();

  const scans = await projectService.listScans(ctx, projectId, 100);

  // Only finished imports carry a graph worth plotting; a queued or failed one
  // has no counts to draw. Oldest first, because time runs left to right.
  const points: RiskHistoryPoint[] = scans
    .filter((scan) => scan.status === 'COMPLETED' && scan.completedAt !== null)
    .map((scan) => ({
      at: (scan.completedAt ?? scan.startedAt ?? new Date()).toISOString(),
      total: scan.totalDeps,
      flagged: scan.flaggedDeps,
      blocked: scan.blockedDeps,
    }))
    .reverse();

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Risk as the graph changed</CardTitle>
          <CardDescription>
            One point per import. A jump in the total is a dependency added; a jump in flagged
            without one is a package that was already installed turning out to be something else.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {points.length === 0 ? (
            <EmptyState
              size="sm"
              icon={History}
              title="No completed import yet"
              description="Upload a lockfile from the tree tab. Each import records the graph it produced, and the second one gives this chart something to compare."
            />
          ) : points.length === 1 ? (
            <div className="space-y-4">
              <RiskHistoryChart points={points} />
              <p className="text-xs text-muted-foreground">
                One import so far, so this is a single reading rather than a trend.
              </p>
            </div>
          ) : (
            <RiskHistoryChart points={points} />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Imports</CardTitle>
          <CardDescription>
            {scans.length === 0
              ? 'Nothing recorded yet.'
              : `The last ${scans.length.toLocaleString('en-GB')} imports of this project, newest first.`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {scans.length === 0 ? (
            <EmptyState size="sm" icon={History} title="No imports recorded" />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <caption className="sr-only">Dependency graph imports for this project</caption>
                <TableHeader>
                  <TableRow>
                    <TableHead>When</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Dependencies</TableHead>
                    <TableHead className="text-right">Change</TableHead>
                    <TableHead className="text-right">Flagged</TableHead>
                    <TableHead className="text-right">Held</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {scans.map((scan, index) => {
                    // `scans` is newest-first, so the previous import is the next row down.
                    const older = scans[index + 1];
                    const when = scan.completedAt ?? scan.startedAt;

                    return (
                      <TableRow key={scan.id}>
                        <TableCell>
                          {when ? (
                            <TimeAgo date={when} className="text-xs text-muted-foreground" />
                          ) : (
                            <span className="text-xs text-muted-foreground">Not started</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={STATUS_VARIANT[scan.status]}
                            className="font-mono text-[11px]"
                          >
                            {scan.status.toLowerCase()}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums">
                          {scan.totalDeps.toLocaleString('en-GB')}
                        </TableCell>
                        <TableCell className="text-right">
                          <Delta current={scan.totalDeps} previous={older?.totalDeps ?? null} />
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums">
                          {scan.flaggedDeps.toLocaleString('en-GB')}
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums">
                          {scan.blockedDeps.toLocaleString('en-GB')}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
