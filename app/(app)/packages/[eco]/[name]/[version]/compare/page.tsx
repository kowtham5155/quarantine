import Link from 'next/link';
import { ArrowRight, GitCompareArrows, Minus, Plus } from 'lucide-react';

import { EmptyState } from '@/components/shared/EmptyState';
import { SignalBadge } from '@/components/shared/SignalBadge';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { requireAuthContext } from '@/lib/auth-context';
import { isVerdict } from '@/lib/constants';
import { NotFoundError } from '@/lib/errors';
import { versionHref } from '@/lib/routes';
import { safeText } from '@/lib/safe-display';
import { compareVersions, type VersionComparison } from '@/lib/services/analysis.service';
import { loadRuleMeta, previousAnalysedVersion } from '@/lib/services/package.service';

import { readVersionParams } from '../../../../params';
import { loadReport } from '../report';

interface PageProps {
  params: Promise<{ eco: string; name: string; version: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

function RuleList({
  title,
  description,
  ruleIds,
  rules,
  tone,
}: {
  title: string;
  description: string;
  ruleIds: string[];
  rules: Awaited<ReturnType<typeof loadRuleMeta>>;
  tone: 'added' | 'removed';
}) {
  const Icon = tone === 'added' ? Plus : Minus;

  return (
    <Card
      className={
        tone === 'added' && ruleIds.length > 0
          ? 'border-verdict-likely-malicious-accent/40'
          : undefined
      }
    >
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Icon
            aria-hidden="true"
            className={`size-4 ${
              tone === 'added'
                ? 'text-verdict-likely-malicious-accent'
                : 'text-verdict-clean-accent'
            }`}
          />
          {title}
          <span className="font-mono text-xs font-normal text-muted-foreground">
            {ruleIds.length}
          </span>
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        {ruleIds.length === 0 ? (
          <p className="text-sm text-muted-foreground">None.</p>
        ) : (
          <ul className="space-y-2">
            {ruleIds.map((ruleId) => {
              const rule = rules.find((candidate) => candidate.ruleId === ruleId);
              return (
                <li key={ruleId} className="flex flex-wrap items-center gap-2 text-sm">
                  {rule ? (
                    <SignalBadge family={rule.family} ruleId={ruleId} compact />
                  ) : (
                    <code className="font-mono text-xs">{ruleId}</code>
                  )}
                  <span className="font-medium">{rule?.name ?? ruleId}</span>
                </li>
              );
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

export default async function ComparePage({ params, searchParams }: PageProps) {
  const ctx = await requireAuthContext();
  const { ecosystem, name, version } = await readVersionParams(params);
  const report = await loadReport(ecosystem, name, version);

  const query = await searchParams;
  const requested = Array.isArray(query.from) ? query.from[0] : query.from;

  const fromVersion =
    requested && requested.length <= 64
      ? requested
      : await previousAnalysedVersion(ctx, ecosystem, name, version);

  const candidates = report.siblingVersions.filter((sibling) => sibling.version !== version);

  if (!fromVersion) {
    return (
      <EmptyState
        icon={GitCompareArrows}
        title="Nothing to compare against"
        description="This organisation has analysed only this version of the package. Scan an earlier version and the two can be diffed."
      />
    );
  }

  let comparison: VersionComparison | null = null;
  let error: string | null = null;

  try {
    comparison = await compareVersions(
      { ...ctx, actorEmail: ctx.email },
      ecosystem,
      name,
      fromVersion,
      version,
    );
  } catch (caught) {
    if (caught instanceof NotFoundError) {
      error = 'Both versions must have been analysed here before they can be compared.';
    } else {
      throw caught;
    }
  }

  const rules = await loadRuleMeta();

  return (
    <div className="space-y-6">
      <div className="max-w-3xl space-y-1">
        <h2 className="text-lg font-semibold tracking-tight">What this version changed</h2>
        <p className="text-sm text-muted-foreground">
          The question a developer bumping a dependency actually has: which rules fire now that did
          not fire before.
        </p>
      </div>

      {candidates.length > 0 ? (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-muted-foreground">Compare against:</span>
          {candidates.slice(0, 12).map((candidate) => (
            <Link
              key={candidate.version}
              href={`${versionHref(ecosystem, name, version, 'compare')}?from=${encodeURIComponent(
                candidate.version,
              )}`}
              className={`rounded-md border px-2 py-0.5 font-mono text-xs ${
                candidate.version === fromVersion
                  ? 'border-primary bg-primary/10 text-foreground'
                  : 'border-border text-muted-foreground hover:text-foreground'
              }`}
            >
              {safeText(candidate.version, { maxLength: 24 })}
            </Link>
          ))}
        </div>
      ) : null}

      {error ? (
        <EmptyState
          icon={GitCompareArrows}
          title="Cannot compare these versions"
          description={error}
        />
      ) : comparison ? (
        <>
          <Card>
            <CardContent className="flex flex-wrap items-center justify-between gap-6 py-6">
              <div className="space-y-1">
                <p className="font-mono text-sm">{safeText(comparison.from.version)}</p>
                {isVerdict(comparison.from.verdict) ? (
                  <VerdictBadge verdict={comparison.from.verdict} size="sm" />
                ) : null}
                <p className="font-mono text-xs text-muted-foreground">
                  score {comparison.from.score?.toFixed(1) ?? '—'}
                </p>
              </div>

              <ArrowRight aria-hidden="true" className="size-5 shrink-0 text-muted-foreground" />

              <div className="space-y-1">
                <p className="font-mono text-sm">{safeText(comparison.to.version)}</p>
                {isVerdict(comparison.to.verdict) ? (
                  <VerdictBadge verdict={comparison.to.verdict} size="sm" />
                ) : null}
                <p className="font-mono text-xs text-muted-foreground">
                  score {comparison.to.score?.toFixed(1) ?? '—'}
                </p>
              </div>

              <div className="space-y-1">
                <p className="text-xs text-muted-foreground">Score delta</p>
                <p
                  className={`font-mono text-2xl tabular-nums ${
                    comparison.scoreDelta > 0
                      ? 'text-verdict-likely-malicious-accent'
                      : comparison.scoreDelta < 0
                        ? 'text-verdict-clean-accent'
                        : 'text-muted-foreground'
                  }`}
                >
                  {comparison.scoreDelta > 0 ? '+' : ''}
                  {comparison.scoreDelta.toFixed(1)}
                </p>
              </div>
            </CardContent>
          </Card>

          <div className="grid gap-4 lg:grid-cols-2">
            <RuleList
              tone="added"
              title="New in this version"
              description="Rules that fire here and did not fire on the earlier version."
              ruleIds={comparison.newSignals}
              rules={rules}
            />
            <RuleList
              tone="removed"
              title="No longer firing"
              description="Rules that fired on the earlier version and no longer do."
              ruleIds={comparison.resolvedSignals}
              rules={rules}
            />
          </div>
        </>
      ) : null}
    </div>
  );
}
