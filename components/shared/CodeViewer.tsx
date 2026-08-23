import { FileCode2 } from 'lucide-react';

import { CopyButton } from '@/components/shared/CopyButton';
import { ScrollArea } from '@/components/ui/scroll-area';
import { stripBidiControls } from '@/lib/safe-display';
import { cn } from '@/lib/utils';

export type HighlightSeverity = 'critical' | 'warning' | 'info';

export interface CodeHighlight {
  /** 1-based, inclusive. */
  startLine: number;
  /** 1-based, inclusive. Defaults to `startLine`. */
  endLine?: number;
  severity?: HighlightSeverity;
  /** Short reason shown in the gutter tooltip, e.g. "Q-INS-002". */
  label?: string;
}

export interface CodeViewerProps {
  code: string;
  /** Shown in the header. Purely a label — nothing is executed or resolved. */
  filename?: string;
  /** Language name for the header chip. No highlighter is run. */
  language?: string;
  highlights?: readonly CodeHighlight[];
  /** Line number the first rendered line corresponds to. */
  startLine?: number;
  /** Cap on rendered lines. Excess is dropped with a notice. */
  maxLines?: number;
  /** Cap on rendered characters per line, so a minified blob cannot stall paint. */
  maxLineLength?: number;
  showCopy?: boolean;
  className?: string;
}

const SEVERITY_CLASSES: Record<HighlightSeverity, { row: string; marker: string }> = {
  critical: {
    row: 'bg-verdict-likely-malicious-surface',
    marker: 'bg-verdict-likely-malicious-accent',
  },
  warning: {
    row: 'bg-verdict-suspicious-surface',
    marker: 'bg-verdict-suspicious-accent',
  },
  info: {
    row: 'bg-primary/10',
    marker: 'bg-primary',
  },
};

interface RenderedLine {
  number: number;
  text: string;
  truncated: boolean;
  severity: HighlightSeverity | null;
  label: string | null;
}

const SEVERITY_RANK: Record<HighlightSeverity, number> = { critical: 3, warning: 2, info: 1 };

/**
 * Read-only source viewer for package content.
 *
 * This renders text, and only text. No syntax highlighter runs over it: every
 * highlighter in the ecosystem works by producing HTML, and injecting HTML
 * derived from an untrusted tarball is exactly the thing THE SAFETY RULE
 * forbids. Bidi control characters are stripped so a Trojan Source payload
 * cannot reorder what an analyst is reading, and both line count and line
 * length are bounded so a minified 8 MB one-liner cannot lock up the tab.
 */
export function CodeViewer({
  code,
  filename,
  language,
  highlights = [],
  startLine = 1,
  maxLines = 2000,
  maxLineLength = 500,
  showCopy = true,
  className,
}: CodeViewerProps) {
  const rawLines = stripBidiControls(code).split(/\r\n?|\n/);
  const overflowed = rawLines.length > maxLines;
  const visible = overflowed ? rawLines.slice(0, maxLines) : rawLines;

  const severityByLine = new Map<number, { severity: HighlightSeverity; label: string | null }>();
  for (const highlight of highlights) {
    const severity = highlight.severity ?? 'warning';
    const end = Math.max(highlight.startLine, highlight.endLine ?? highlight.startLine);
    for (let line = highlight.startLine; line <= end; line++) {
      const existing = severityByLine.get(line);
      if (!existing || SEVERITY_RANK[severity] > SEVERITY_RANK[existing.severity]) {
        severityByLine.set(line, { severity, label: highlight.label ?? null });
      }
    }
  }

  const lines: RenderedLine[] = visible.map((text, index) => {
    const number = startLine + index;
    const marked = severityByLine.get(number);
    const truncated = text.length > maxLineLength;
    return {
      number,
      text: truncated ? `${text.slice(0, maxLineLength)} …` : text,
      truncated,
      severity: marked?.severity ?? null,
      label: marked?.label ?? null,
    };
  });

  const gutterWidth = `${String(startLine + visible.length).length + 1}ch`;

  return (
    <div className={cn('overflow-hidden rounded-lg border border-border bg-surface', className)}>
      {filename || language || showCopy ? (
        <div className="flex items-center gap-2 border-b border-border bg-muted/40 px-3 py-2">
          <FileCode2 aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
          <span className="break-anywhere min-w-0 truncate font-mono text-xs">
            {filename ?? 'source'}
          </span>
          {language ? (
            <span className="shrink-0 rounded border border-border px-1.5 py-px font-mono text-[10px] text-muted-foreground uppercase">
              {language}
            </span>
          ) : null}
          {showCopy ? (
            <CopyButton value={code} label="Copy source" className="ml-auto size-7" />
          ) : null}
        </div>
      ) : null}

      <ScrollArea className="max-h-[32rem]">
        <pre className="w-max min-w-full font-mono text-xs leading-relaxed">
          <code>
            {lines.map((line) => {
              const severityClass = line.severity ? SEVERITY_CLASSES[line.severity] : null;
              return (
                <span
                  key={line.number}
                  data-line={line.number}
                  className={cn('flex w-full', severityClass?.row)}
                >
                  <span
                    aria-hidden="true"
                    className={cn('w-0.5 shrink-0', severityClass?.marker ?? 'bg-transparent')}
                  />
                  <span
                    aria-hidden="true"
                    style={{ width: gutterWidth }}
                    className="shrink-0 pr-3 pl-2 text-right text-muted-foreground/70 tabular-nums select-none"
                  >
                    {line.number}
                  </span>
                  <span className="pr-4 whitespace-pre">{line.text === '' ? ' ' : line.text}</span>
                  {line.label ? (
                    <span className="shrink-0 pr-3 pl-4 text-[10px] tracking-wide text-muted-foreground uppercase">
                      {line.label}
                    </span>
                  ) : null}
                </span>
              );
            })}
          </code>
        </pre>
      </ScrollArea>

      {overflowed ? (
        <p className="border-t border-border px-3 py-2 text-xs text-muted-foreground">
          Showing the first {maxLines.toLocaleString()} of {rawLines.length.toLocaleString()} lines.
        </p>
      ) : null}
    </div>
  );
}
