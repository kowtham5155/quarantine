import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import Link from 'next/link';

import { PageHeader } from '@/components/shared/PageHeader';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { packageHref, versionHref } from '@/lib/routes';
import { safeText } from '@/lib/safe-display';

import { readVersionParams } from '../../../params';
import { loadReport } from './report';
import { VersionTabs } from './VersionTabs';

interface LayoutProps {
  children: ReactNode;
  params: Promise<{ eco: string; name: string; version: string }>;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ eco: string; name: string; version: string }>;
}): Promise<Metadata> {
  const { name, version } = await readVersionParams(params);
  return {
    title: `${safeText(name, { maxLength: 100 })}@${safeText(version, { maxLength: 40 })}`,
  };
}

export default async function VersionLayout({ children, params }: LayoutProps) {
  const { ecosystem, name, version } = await readVersionParams(params);
  const report = await loadReport(ecosystem, name, version);

  const base = versionHref(ecosystem, name, version);
  const firedRules = new Set(report.hits.map((hit) => hit.ruleId)).size;
  const files = new Set(report.hits.map((hit) => hit.filePath).filter(Boolean)).size;

  return (
    <div className="space-y-6">
      <PageHeader
        separated={false}
        breadcrumbs={[
          { label: 'Packages', href: '/packages' },
          { label: safeText(name, { maxLength: 40 }), href: packageHref(ecosystem, name) },
          { label: safeText(version, { maxLength: 24 }) },
        ]}
        title={
          <span className="break-anywhere font-mono">
            {safeText(name)}
            <span className="text-muted-foreground">@{safeText(version)}</span>
          </span>
        }
        meta={
          <>
            {report.analysis.verdict ? (
              <VerdictBadge verdict={report.analysis.verdict} appearance="solid" />
            ) : (
              <Badge variant="secondary">{report.analysis.status}</Badge>
            )}
            {report.analysis.status === 'PARTIAL' ? (
              <Badge variant="outline" className="text-xs">
                Partial analysis
              </Badge>
            ) : null}
            <span className="font-mono text-xs text-muted-foreground">
              engine {report.analysis.engineVersion}
            </span>
          </>
        }
        actions={
          <Button asChild variant="outline">
            <Link href={`/analyses/${report.analysis.analysisId}`}>Analysis record</Link>
          </Button>
        }
      />

      <VersionTabs
        base={base}
        counts={{ signals: firedRules, files, provenance: report.provenance ? undefined : 0 }}
      />

      <div>{children}</div>
    </div>
  );
}
