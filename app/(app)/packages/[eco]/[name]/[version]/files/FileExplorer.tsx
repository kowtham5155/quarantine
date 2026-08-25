'use client';

import { useMemo, useState } from 'react';
import { FileCode2, Folder } from 'lucide-react';

import { CodeViewer } from '@/components/shared/CodeViewer';
import { SignalBadge } from '@/components/shared/SignalBadge';
import { SIGNAL_FAMILY_META } from '@/lib/constants';
import { safeText } from '@/lib/safe-display';
import type { FileRiskRow } from '@/lib/services/package.service';
import { cn } from '@/lib/utils';

export interface FileExplorerProps {
  files: FileRiskRow[];
}

const SEVERITY_SHADE: Record<string, string> = {
  CRITICAL: 'bg-verdict-known-malicious',
  HIGH: 'bg-verdict-likely-malicious',
  MEDIUM: 'bg-verdict-suspicious',
  LOW: 'bg-verdict-low-risk',
  INFO: 'bg-muted-foreground',
};

function directoryOf(path: string): string {
  const index = path.lastIndexOf('/');
  return index === -1 ? '.' : path.slice(0, index);
}

function baseName(path: string): string {
  const index = path.lastIndexOf('/');
  return index === -1 ? path : path.slice(index + 1);
}

/**
 * Flagged files, grouped by directory, with the evidence for each.
 *
 * Every path and excerpt here came out of the analysed archive. They are
 * rendered as text through `safeText` and the CodeViewer, which strips bidi
 * controls and runs no highlighter — nothing on this page ever becomes markup.
 */
export function FileExplorer({ files }: FileExplorerProps) {
  const [selectedPath, setSelectedPath] = useState<string>(files[0]?.path ?? '');

  const grouped = useMemo(() => {
    const map = new Map<string, FileRiskRow[]>();
    for (const file of files) {
      const directory = directoryOf(file.path);
      const existing = map.get(directory);
      if (existing) existing.push(file);
      else map.set(directory, [file]);
    }
    return [...map.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [files]);

  const maxRisk = files.reduce((best, file) => Math.max(best, file.risk), 0);
  const selected = files.find((file) => file.path === selectedPath) ?? files[0];

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,20rem)_1fr]">
      <div className="overflow-hidden rounded-lg border border-border">
        <div className="border-b border-border bg-muted/40 px-3 py-2 text-xs font-medium text-muted-foreground">
          {files.length} flagged {files.length === 1 ? 'file' : 'files'}
        </div>
        <ul className="max-h-[36rem] overflow-y-auto p-1">
          {grouped.map(([directory, entries]) => (
            <li key={directory}>
              <p className="flex items-center gap-1.5 px-2 py-1.5 font-mono text-[11px] text-muted-foreground">
                <Folder aria-hidden="true" className="size-3" />
                <span className="break-anywhere min-w-0 truncate">
                  {safeText(directory, { maxLength: 120 })}
                </span>
              </p>
              <ul>
                {entries.map((file) => {
                  const active = file.path === selected?.path;
                  const share = maxRisk === 0 ? 0 : (file.risk / maxRisk) * 100;

                  return (
                    <li key={file.path}>
                      <button
                        type="button"
                        onClick={() => setSelectedPath(file.path)}
                        aria-current={active ? 'true' : undefined}
                        className={cn(
                          'w-full space-y-1 rounded-md px-2 py-1.5 text-left transition-colors',
                          active ? 'bg-surface-raised' : 'hover:bg-surface',
                        )}
                      >
                        <span className="flex items-center gap-1.5">
                          <FileCode2
                            aria-hidden="true"
                            className="size-3.5 shrink-0 text-muted-foreground"
                          />
                          <span className="break-anywhere min-w-0 truncate font-mono text-xs">
                            {safeText(baseName(file.path), { maxLength: 80 })}
                          </span>
                          <span className="ml-auto shrink-0 font-mono text-[10px] text-muted-foreground tabular-nums">
                            {file.risk.toFixed(1)}
                          </span>
                        </span>
                        <span className="block h-1 w-full overflow-hidden rounded-full bg-muted">
                          <span
                            className={cn(
                              'block h-full rounded-full',
                              SEVERITY_SHADE[file.worstSeverity] ?? 'bg-muted-foreground',
                            )}
                            style={{ width: `${Math.max(share, 4)}%` }}
                          />
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </li>
          ))}
        </ul>
      </div>

      <div className="space-y-4">
        {selected ? (
          <>
            <div className="space-y-2">
              <h3 className="break-anywhere font-mono text-sm">
                {safeText(selected.path, { maxLength: 300 })}
              </h3>
              <div className="flex flex-wrap items-center gap-2">
                {selected.families.map((family) => (
                  <SignalBadge key={family} family={family} />
                ))}
                <span className="font-mono text-xs text-muted-foreground">
                  risk {selected.risk.toFixed(2)} · {selected.flaggedLines} flagged{' '}
                  {selected.flaggedLines === 1 ? 'line' : 'lines'} · {selected.ruleIds.length}{' '}
                  {selected.ruleIds.length === 1 ? 'rule' : 'rules'}
                </span>
              </div>
            </div>

            <ul className="space-y-4">
              {selected.hits.map((hit) => (
                <li key={hit.id} className="space-y-2">
                  <p className="flex flex-wrap items-center gap-2 text-xs">
                    <code
                      className="rounded px-1.5 py-0.5 font-mono"
                      style={{
                        backgroundColor: `${SIGNAL_FAMILY_META[hit.family].hex}1a`,
                        color: SIGNAL_FAMILY_META[hit.family].hex,
                      }}
                    >
                      {hit.ruleId}
                    </code>
                    <span className="text-muted-foreground">
                      {hit.lineStart
                        ? `line ${hit.lineStart}${
                            hit.lineEnd && hit.lineEnd !== hit.lineStart ? `–${hit.lineEnd}` : ''
                          }`
                        : 'no line recorded'}
                    </span>
                  </p>

                  {hit.excerpt ? (
                    <CodeViewer
                      code={hit.excerpt}
                      filename={safeText(selected.path, { maxLength: 120 })}
                      startLine={hit.lineStart ?? 1}
                      maxLines={40}
                      highlights={
                        hit.lineStart
                          ? [
                              {
                                startLine: hit.lineStart,
                                endLine: hit.lineEnd ?? hit.lineStart,
                                severity: 'critical',
                                label: hit.ruleId,
                              },
                            ]
                          : []
                      }
                    />
                  ) : (
                    <p className="text-xs text-muted-foreground">
                      This rule recorded no source excerpt — it matched on metadata rather than on a
                      line of code.
                    </p>
                  )}
                </li>
              ))}
            </ul>
          </>
        ) : null}
      </div>
    </div>
  );
}
