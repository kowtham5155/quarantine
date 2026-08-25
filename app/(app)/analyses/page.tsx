import type { Metadata } from 'next';
import Link from 'next/link';
import { Radar } from 'lucide-react';

import { PageHeader } from '@/components/shared/PageHeader';
import { StatCard } from '@/components/shared/StatCard';
import { Button } from '@/components/ui/button';
import { requireAuthContext } from '@/lib/auth-context';
import { isVerdict } from '@/lib/constants';
import { listAnalyses } from '@/lib/services/analysis.service';

import { AnalysesTable, type AnalysisRow } from './AnalysesTable';

export const metadata: Metadata = { title: 'Analyses' };

export default async function AnalysesPage() {
  const ctx = await requireAuthContext();
  const { items, total, take } = await listAnalyses(
    { ...ctx, actorEmail: ctx.email },
    { take: 100 },
  );

  const rows: AnalysisRow[] = items.map((analysis) => ({
    id: analysis.id,
    ecosystem: analysis.packageVersion.package.ecosystem,
    name: analysis.packageVersion.package.name,
    version: analysis.packageVersion.version,
    status: analysis.status,
    verdict: isVerdict(analysis.verdict) ? analysis.verdict : null,
    confidence: analysis.confidence,
    weightedScore: analysis.weightedScore,
    durationMs: analysis.durationMs,
    createdAt: analysis.createdAt.toISOString(),
    completedAt: analysis.completedAt ? analysis.completedAt.toISOString() : null,
  }));

  const queued = rows.filter((row) => row.status === 'QUEUED' || row.status === 'RUNNING').length;
  const failed = rows.filter((row) => row.status === 'FAILED').length;

  return (
    <div className="space-y-8">
      <PageHeader
        title="Analyses"
        description="Every run this organisation has started, in order. A failed run is kept — an analysis that could not complete is a fact about the package too."
        actions={
          <Button asChild>
            <Link href="/scan">
              <Radar aria-hidden="true" />
              New scan
            </Link>
          </Button>
        }
      />

      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard
          label="Runs"
          value={total}
          hint={total > take ? `showing ${take}` : 'all shown'}
        />
        <StatCard label="In flight" value={queued} hint="queued or running" />
        <StatCard label="Failed" value={failed} hint="can be re-run" />
      </div>

      <AnalysesTable analyses={rows} />
    </div>
  );
}
