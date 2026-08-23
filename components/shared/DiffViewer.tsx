import { GitCompareArrows } from 'lucide-react';

import { ScrollArea } from '@/components/ui/scroll-area';
import { collapseUnchanged, diffLines, type DiffLine } from '@/lib/diff';
import { stripBidiControls } from '@/lib/safe-display';
import { cn } from '@/lib/utils';

export interface DiffViewerProps {
  /** Left-hand side — the repository at the resolved tag. */
  original: string;
  /** Right-hand side — what was actually published in the tarball. */
  modified: string;
  filename?: string;
  originalLabel?: string;
  modifiedLabel?: string;
  /** Unchanged lines kept around each change. */
  context?: number;
  /** Cap on rendered characters per line. */
  maxLineLength?: number;
  className?: string;
}

const OP_STYLES = {
  insert: {
    row: 'bg-verdict-clean-surface',
    sign: '+',
    signClass: 'text-verdict-clean-accent',
  },
  delete: {
    row: 'bg-verdict-likely-malicious-surface',
    sign: '-',
    signClass: 'text-verdict-likely-malicious-accent',
  },
  equal: {
    row: '',
    sign: ' ',
    signClass: 'text-muted-foreground/50',
  },
} as const;

function LineRow({ line, maxLineLength }: { line: DiffLine; maxLineLength: number }) {
  const style = OP_STYLES[line.op];
  const text = stripBidiControls(line.content);
  const shown = text.length > maxLineLength ? `${text.slice(0, maxLineLength)} …` : text;

  return (
    <span className={cn('flex w-full', style.row)}>
      <span
        aria-hidden="true"
        className="w-[5ch] shrink-0 pr-2 text-right text-muted-foreground/70 tabular-nums select-none"
      >
        {line.leftLine ?? ''}
      </span>
      <span
        aria-hidden="true"
        className="w-[5ch] shrink-0 pr-2 text-right text-muted-foreground/70 tabular-nums select-none"
      >
        {line.rightLine ?? ''}
      </span>
      <span aria-hidden="true" className={cn('w-[2ch] shrink-0 select-none', style.signClass)}>
        {style.sign}
      </span>
      <span className="pr-4 whitespace-pre">{shown === '' ? ' ' : shown}</span>
    </span>
  );
}

/**
 * Unified diff between the repository source and the published tarball — the
 * evidence view for signal family 6. Files present in the tarball and absent
 * from the repository are the event-stream signature, so a wholly added file
 * shows here as an all-green block with nothing on the left.
 *
 * Content is rendered as escaped text with bidi controls stripped, for the same
 * reason as CodeViewer: both sides are untrusted.
 */
export function DiffViewer({
  original,
  modified,
  filename,
  originalLabel = 'repository',
  modifiedLabel = 'tarball',
  context = 3,
  maxLineLength = 500,
  className,
}: DiffViewerProps) {
  const result = diffLines(original, modified);
  const chunks = collapseUnchanged(result.lines, { context });
  const identical = result.added === 0 && result.removed === 0;

  return (
    <div className={cn('overflow-hidden rounded-lg border border-border bg-surface', className)}>
      <div className="flex flex-wrap items-center gap-2 border-b border-border bg-muted/40 px-3 py-2">
        <GitCompareArrows aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
        <span className="break-anywhere min-w-0 truncate font-mono text-xs">
          {filename ?? 'file'}
        </span>
        <span className="ml-auto font-mono text-xs text-muted-foreground tabular-nums">
          <span className="text-verdict-likely-malicious-accent">−{result.removed}</span>{' '}
          <span className="text-verdict-clean-accent">+{result.added}</span>
        </span>
      </div>

      <div className="flex gap-4 border-b border-border px-3 py-1.5 text-[11px] text-muted-foreground">
        <span>
          <span className="text-verdict-likely-malicious-accent">−</span> {originalLabel}
        </span>
        <span>
          <span className="text-verdict-clean-accent">+</span> {modifiedLabel}
        </span>
        {result.truncated ? (
          <span className="ml-auto">Large file — lines aligned positionally, not by content.</span>
        ) : null}
      </div>

      {identical ? (
        <p className="px-3 py-6 text-center text-sm text-muted-foreground">
          The published file is byte-identical to the repository source.
        </p>
      ) : (
        <ScrollArea className="max-h-[32rem]">
          <pre className="w-max min-w-full font-mono text-xs leading-relaxed">
            <code>
              {chunks.map((chunk, index) =>
                chunk.kind === 'gap' ? (
                  <span
                    key={`gap-${index}`}
                    className="flex w-full bg-muted/40 px-3 py-1 text-[11px] text-muted-foreground italic"
                  >
                    {chunk.hiddenCount} unchanged {chunk.hiddenCount === 1 ? 'line' : 'lines'}{' '}
                    hidden
                  </span>
                ) : (
                  chunk.lines.map((line, lineIndex) => (
                    <LineRow
                      key={`line-${index}-${lineIndex}`}
                      line={line}
                      maxLineLength={maxLineLength}
                    />
                  ))
                ),
              )}
            </code>
          </pre>
        </ScrollArea>
      )}
    </div>
  );
}
