'use client';

import { useMemo, useState } from 'react';
import { ExternalLink, ScrollText } from 'lucide-react';

import { DataTable, type DataTableColumn } from '@/components/shared/DataTable';
import { EmptyState } from '@/components/shared/EmptyState';
import { SignalBadge } from '@/components/shared/SignalBadge';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { SIGNAL_FAMILIES, SIGNAL_FAMILY_META, SIGNAL_SEVERITIES } from '@/lib/constants';
import type { RuleCatalogueEntry } from '@/lib/services/catalogue.service';

const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: 'bg-verdict-known-malicious-surface text-verdict-known-malicious-accent',
  HIGH: 'bg-verdict-likely-malicious-surface text-verdict-likely-malicious-accent',
  MEDIUM: 'bg-verdict-suspicious-surface text-verdict-suspicious-accent',
  LOW: 'bg-verdict-low-risk-surface text-verdict-low-risk-accent',
  INFO: 'bg-muted text-muted-foreground',
};

function SeverityChip({ severity }: { severity: string }) {
  return (
    <span
      className={`inline-flex h-5 items-center rounded px-1.5 font-mono text-[11px] font-medium ${
        SEVERITY_CLASS[severity] ?? SEVERITY_CLASS.INFO
      }`}
    >
      {severity}
    </span>
  );
}

export interface RuleCatalogueProps {
  rules: RuleCatalogueEntry[];
  initialFamily?: string;
}

/**
 * The public rule catalogue.
 *
 * Every field here is written by us, not by a package, so it is ordinary text —
 * but it is still rendered as text and never as markup, because the catalogue
 * is the one place a reader is most likely to trust what they see.
 */
export function RuleCatalogue({ rules, initialFamily }: RuleCatalogueProps) {
  const [selected, setSelected] = useState<RuleCatalogueEntry | null>(null);

  const data = useMemo(() => {
    if (!initialFamily) return rules;
    return rules.filter((rule) => rule.family === initialFamily);
  }, [rules, initialFamily]);

  const columns: Array<DataTableColumn<RuleCatalogueEntry>> = [
    {
      id: 'ruleId',
      header: 'Rule',
      cell: (rule) => <code className="font-mono text-xs">{rule.ruleId}</code>,
      sortValue: (rule) => rule.ruleId,
      searchValue: (rule) => rule.ruleId,
    },
    {
      id: 'name',
      header: 'Name',
      cell: (rule) => (
        <div className="min-w-0">
          <p className="text-sm font-medium">{rule.name}</p>
          <p className="line-clamp-1 text-xs text-muted-foreground">{rule.description}</p>
        </div>
      ),
      sortValue: (rule) => rule.name,
      searchValue: (rule) => `${rule.name} ${rule.description} ${rule.remediation}`,
      className: 'max-w-md',
    },
    {
      id: 'family',
      header: 'Family',
      cell: (rule) => <SignalBadge family={rule.family} />,
      sortValue: (rule) => rule.family,
      searchValue: (rule) => SIGNAL_FAMILY_META[rule.family].label,
      hideBelowSm: true,
    },
    {
      id: 'severity',
      header: 'Severity',
      cell: (rule) => <SeverityChip severity={rule.severity} />,
      sortValue: (rule) => rule.severity,
      hideBelowSm: true,
    },
    {
      id: 'weight',
      header: 'Weight',
      align: 'right',
      cell: (rule) => <span className="font-mono text-xs tabular-nums">{rule.baseWeight}</span>,
      sortValue: (rule) => rule.baseWeight,
    },
    {
      id: 'status',
      header: 'Status',
      cell: (rule) =>
        rule.enabled ? (
          <Badge variant="outline" className="text-xs">
            Enabled
          </Badge>
        ) : (
          <Badge variant="secondary" className="text-xs">
            Disabled
          </Badge>
        ),
      sortValue: (rule) => (rule.enabled ? 'enabled' : 'disabled'),
      hideBelowSm: true,
    },
  ];

  return (
    <>
      <DataTable
        data={data}
        columns={columns}
        getRowId={(rule) => rule.ruleId}
        searchPlaceholder="Search rules, descriptions, remediation…"
        caption="The complete detection rule catalogue"
        initialSort={{ columnId: 'ruleId', direction: 'asc' }}
        pageSize={25}
        onRowClick={(rule) => setSelected(rule)}
        facets={[
          {
            id: 'family',
            label: 'Family',
            options: SIGNAL_FAMILIES.map((family) => ({
              value: family,
              label: SIGNAL_FAMILY_META[family].label,
            })),
            accessor: (rule) => rule.family,
          },
          {
            id: 'severity',
            label: 'Severity',
            options: SIGNAL_SEVERITIES.map((severity) => ({ value: severity, label: severity })),
            accessor: (rule) => rule.severity,
          },
        ]}
        emptyState={
          <EmptyState
            icon={ScrollText}
            title="No rules in the catalogue"
            description="The rule catalogue has not been seeded for this deployment."
          />
        }
        noResultsState={
          <EmptyState
            size="sm"
            icon={ScrollText}
            title="No rule matches that filter"
            description="Try a different family, severity or search term."
          />
        }
      />

      <Dialog open={selected !== null} onOpenChange={(open) => !open && setSelected(null)}>
        <DialogContent className="max-h-[85svh] overflow-y-auto sm:max-w-2xl">
          {selected ? (
            <>
              <DialogHeader>
                <DialogTitle className="flex flex-wrap items-center gap-2">
                  <code className="font-mono text-sm">{selected.ruleId}</code>
                  <span>{selected.name}</span>
                </DialogTitle>
                <DialogDescription>{selected.description}</DialogDescription>
              </DialogHeader>

              <div className="flex flex-wrap items-center gap-2">
                <SignalBadge family={selected.family} />
                <SeverityChip severity={selected.severity} />
                <span className="font-mono text-xs text-muted-foreground">
                  weight {selected.baseWeight}
                </span>
                {selected.corpusCoverage > 0 ? (
                  <span className="text-xs text-muted-foreground">
                    expected on {selected.corpusCoverage} corpus{' '}
                    {selected.corpusCoverage === 1 ? 'entry' : 'entries'}
                  </span>
                ) : null}
              </div>

              <section className="space-y-1.5">
                <h3 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">
                  Remediation
                </h3>
                <p className="text-sm">{selected.remediation}</p>
              </section>

              {selected.falsePositiveNotes ? (
                <section className="space-y-1.5">
                  <h3 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">
                    Known false positives
                  </h3>
                  <p className="text-sm text-muted-foreground">{selected.falsePositiveNotes}</p>
                </section>
              ) : null}

              {selected.references.length > 0 ? (
                <section className="space-y-1.5">
                  <h3 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">
                    References
                  </h3>
                  <ul className="space-y-1">
                    {selected.references.map((reference) => (
                      <li key={reference} className="flex items-start gap-1.5 text-sm">
                        <ExternalLink
                          aria-hidden="true"
                          className="mt-0.5 size-3.5 shrink-0 text-muted-foreground"
                        />
                        <span className="break-anywhere min-w-0 font-mono text-xs">
                          {reference}
                        </span>
                      </li>
                    ))}
                  </ul>
                </section>
              ) : null}
            </>
          ) : null}
        </DialogContent>
      </Dialog>
    </>
  );
}
