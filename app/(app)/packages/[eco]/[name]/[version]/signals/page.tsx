import { Check, CircleSlash, MinusCircle } from 'lucide-react';

import { CodeViewer } from '@/components/shared/CodeViewer';
import { SignalBadge } from '@/components/shared/SignalBadge';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion';
import { Badge } from '@/components/ui/badge';
import { SIGNAL_FAMILIES, SIGNAL_FAMILY_META } from '@/lib/constants';
import { safeText } from '@/lib/safe-display';

import { readVersionParams } from '../../../../params';
import { loadReport } from '../report';

interface PageProps {
  params: Promise<{ eco: string; name: string; version: string }>;
}

/**
 * Why a rule that did not fire is worth a row.
 *
 * Only fired signals are persisted, so "not fired" here means "evaluated and
 * did not match" — except in the provenance family, where the recorded check
 * status tells us the rule could not be evaluated at all. Presenting "we could
 * not check" as "it passed" would be the single most misleading thing this page
 * could do, so that case is labelled separately.
 */
const PROVENANCE_SKIP_LABEL: Record<string, string> = {
  NO_REPO: 'Not evaluated — the package declares no repository',
  REPO_UNREACHABLE: 'Not evaluated — the repository could not be read',
  NO_TAG: 'Not evaluated — no repository tag matched this version',
};

export default async function SignalsPage({ params }: PageProps) {
  const { ecosystem, name, version } = await readVersionParams(params);
  const report = await loadReport(ecosystem, name, version);

  const hitsByRule = new Map<string, (typeof report.hits)[number][]>();
  for (const hit of report.hits) {
    const existing = hitsByRule.get(hit.ruleId);
    if (existing) existing.push(hit);
    else hitsByRule.set(hit.ruleId, [hit]);
  }

  const provenanceSkip =
    report.provenance &&
    report.provenance.status !== 'MATCH' &&
    report.provenance.status !== 'DIVERGENT'
      ? PROVENANCE_SKIP_LABEL[report.provenance.status]
      : undefined;

  return (
    <div className="space-y-6">
      <div className="max-w-3xl space-y-1">
        <h2 className="text-lg font-semibold tracking-tight">Every rule, fired and not fired</h2>
        <p className="text-sm text-muted-foreground">
          {report.rules.length} rules in the catalogue, {hitsByRule.size} of which matched this
          artefact. A report that only lists hits cannot answer &ldquo;did you check for
          that?&rdquo;, and the answer to that question is most of what makes a verdict trustworthy.
        </p>
      </div>

      <Accordion
        type="multiple"
        defaultValue={SIGNAL_FAMILIES.filter((family) =>
          report.hits.some((hit) => hit.family === family),
        )}
        className="space-y-3"
      >
        {SIGNAL_FAMILIES.map((family) => {
          const familyMeta = SIGNAL_FAMILY_META[family];
          const rules = report.rules
            .filter((rule) => rule.family === family)
            .sort((a, b) => a.ruleId.localeCompare(b.ruleId));
          const breakdown = report.families.find((row) => row.family === family);

          return (
            <AccordionItem
              key={family}
              value={family}
              className="rounded-lg border border-border px-4"
            >
              <AccordionTrigger className="hover:no-underline">
                <div className="flex flex-1 flex-wrap items-center justify-between gap-3 pr-3">
                  <div className="flex items-center gap-2">
                    <SignalBadge family={family} />
                    <span className="text-sm text-muted-foreground">{familyMeta.description}</span>
                  </div>
                  <span className="font-mono text-xs text-muted-foreground tabular-nums">
                    {breakdown?.fired ?? 0}/{rules.length} fired
                  </span>
                </div>
              </AccordionTrigger>

              <AccordionContent className="space-y-3 pb-4">
                {rules.map((rule) => {
                  const hits = hitsByRule.get(rule.ruleId) ?? [];
                  const fired = hits.length > 0;
                  const first = hits[0];
                  const skipped = !fired && family === 'PROVENANCE' ? provenanceSkip : undefined;

                  return (
                    <div
                      key={rule.ruleId}
                      className={`rounded-md border p-3 ${
                        fired ? 'border-border bg-surface/60' : 'border-border/60'
                      }`}
                    >
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <div className="min-w-0 space-y-1">
                          <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
                            <code className="font-mono text-xs">{rule.ruleId}</code>
                            {rule.name}
                            {!rule.enabled ? (
                              <Badge variant="secondary" className="text-[10px]">
                                Disabled
                              </Badge>
                            ) : null}
                          </p>
                          <p className="text-xs text-muted-foreground">{rule.description}</p>
                        </div>

                        <span
                          className={`flex shrink-0 items-center gap-1.5 text-xs font-medium ${
                            fired
                              ? 'text-verdict-suspicious-accent'
                              : skipped
                                ? 'text-verdict-low-risk-accent'
                                : 'text-muted-foreground'
                          }`}
                        >
                          {fired ? (
                            <>
                              <Check aria-hidden="true" className="size-3.5" />
                              Fired
                            </>
                          ) : skipped ? (
                            <>
                              <MinusCircle aria-hidden="true" className="size-3.5" />
                              Not evaluated
                            </>
                          ) : (
                            <>
                              <CircleSlash aria-hidden="true" className="size-3.5" />
                              Did not fire
                            </>
                          )}
                        </span>
                      </div>

                      {skipped ? (
                        <p className="mt-2 text-xs text-verdict-low-risk-accent">{skipped}</p>
                      ) : null}

                      {fired && first ? (
                        <>
                          <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1 font-mono text-xs text-muted-foreground">
                            <span>weight {first.weight.toFixed(1)}</span>
                            <span>confidence {(first.confidence * 100).toFixed(0)}%</span>
                            <span>context ×{first.contextModifier.toFixed(2)}</span>
                            <span>severity {first.severity}</span>
                            <span>
                              contribution{' '}
                              {(first.weight * first.confidence * first.contextModifier).toFixed(2)}
                            </span>
                          </div>

                          <ul className="mt-3 space-y-3">
                            {hits.slice(0, 10).map((hit) => (
                              <li key={hit.id} className="space-y-1.5">
                                {hit.filePath ? (
                                  <p className="break-anywhere font-mono text-xs text-muted-foreground">
                                    {safeText(hit.filePath, { maxLength: 200 })}
                                    {hit.lineStart
                                      ? `:${hit.lineStart}${
                                          hit.lineEnd && hit.lineEnd !== hit.lineStart
                                            ? `-${hit.lineEnd}`
                                            : ''
                                        }`
                                      : ''}
                                  </p>
                                ) : null}

                                {hit.excerpt ? (
                                  <CodeViewer
                                    code={hit.excerpt}
                                    startLine={hit.lineStart ?? 1}
                                    maxLines={12}
                                    showCopy={false}
                                  />
                                ) : null}

                                {Object.keys(hit.evidence).length > 0 ? (
                                  <dl className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                                    {Object.entries(hit.evidence)
                                      .slice(0, 8)
                                      .map(([key, value]) => (
                                        <div key={key} className="flex gap-1">
                                          <dt className="font-medium">
                                            {safeText(key, { maxLength: 40 })}
                                          </dt>
                                          <dd className="break-anywhere font-mono">
                                            {safeText(String(value), { maxLength: 120 })}
                                          </dd>
                                        </div>
                                      ))}
                                  </dl>
                                ) : null}
                              </li>
                            ))}
                          </ul>

                          {hits.length > 10 ? (
                            <p className="mt-2 text-xs text-muted-foreground">
                              Showing 10 of {hits.length} occurrences.
                            </p>
                          ) : null}

                          <p className="mt-3 text-xs text-muted-foreground">
                            <span className="font-medium text-foreground">Remediation.</span>{' '}
                            {rule.remediation}
                          </p>

                          {rule.falsePositiveNotes ? (
                            <p className="mt-1.5 text-xs text-muted-foreground">
                              <span className="font-medium text-foreground">
                                Known false positives.
                              </span>{' '}
                              {rule.falsePositiveNotes}
                            </p>
                          ) : null}
                        </>
                      ) : null}
                    </div>
                  );
                })}
              </AccordionContent>
            </AccordionItem>
          );
        })}
      </Accordion>
    </div>
  );
}
