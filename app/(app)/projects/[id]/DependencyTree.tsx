'use client';

import { useCallback, useMemo, useState } from 'react';
import Link from 'next/link';
import { ChevronDown, ChevronRight, Layers, ShieldAlert } from 'lucide-react';

import { EmptyState } from '@/components/shared/EmptyState';
import { PackageRef } from '@/components/shared/PackageRef';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { VERDICT_META, type Verdict } from '@/lib/constants';
import { ecosystemSlug, versionHref } from '@/lib/routes';
import type { DependencyTreeNode } from '@/lib/services/project.service';
import { cn } from '@/lib/utils';

/** Rows rendered in one pass. More than this and the browser, not the tree, is the bottleneck. */
const RENDER_BUDGET = 300;

/** Depth expanded on first paint. Direct dependencies open, their tail closed. */
const INITIAL_DEPTH = 1;

export interface DependencyTreeProps {
  nodes: DependencyTreeNode[];
  flaggedCount: number;
}

interface VisibleRow {
  node: DependencyTreeNode;
  indent: number;
  expandable: boolean;
  expanded: boolean;
}

function isFlagged(verdict: Verdict | null): boolean {
  return (
    verdict === 'SUSPICIOUS' || verdict === 'LIKELY_MALICIOUS' || verdict === 'KNOWN_MALICIOUS'
  );
}

/** Every node id that sits at or above `depth`, for the initial expansion set. */
function idsToDepth(nodes: readonly DependencyTreeNode[], depth: number): Set<string> {
  const open = new Set<string>();

  const walk = (node: DependencyTreeNode, level: number): void => {
    if (level >= depth) return;
    open.add(node.id);
    for (const child of node.children) walk(child, level + 1);
  };

  for (const node of nodes) walk(node, 0);
  return open;
}

/**
 * The dependency graph as a tree, with this org's verdict on every node.
 *
 * Only the rows the reader can actually see are built: collapsed subtrees cost
 * nothing, and the flattened visible list is cut at a render budget with an
 * explicit "show more" rather than silently truncating. That keeps a
 * 1,500-package graph responsive without a virtualisation library, and it never
 * lies about how much is on screen.
 *
 * A package name is attacker-controlled and rendered through `PackageRef`,
 * which bounds its length and strips bidi and zero-width characters.
 */
export function DependencyTree({ nodes, flaggedCount }: DependencyTreeProps) {
  const [expanded, setExpanded] = useState<Set<string>>(() => idsToDepth(nodes, INITIAL_DEPTH));
  const [query, setQuery] = useState('');
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const [limit, setLimit] = useState(RENDER_BUDGET);

  const needle = query.trim().toLowerCase();

  /**
   * A node survives the filter when it matches itself or when something in its
   * subtree does — hiding a matching package because its parent did not match
   * would make the search useless on a transitive dependency.
   */
  const keep = useCallback(
    (node: DependencyTreeNode): boolean => {
      const selfMatches =
        (needle.length === 0 || node.name.toLowerCase().includes(needle)) &&
        (!flaggedOnly || isFlagged(node.verdict));
      if (selfMatches) return true;
      return node.children.some(keep);
    },
    [needle, flaggedOnly],
  );

  const filtering = needle.length > 0 || flaggedOnly;

  const rows = useMemo(() => {
    const out: VisibleRow[] = [];

    const walk = (node: DependencyTreeNode, indent: number): void => {
      if (filtering && !keep(node)) return;

      const children = filtering ? node.children.filter(keep) : node.children;
      // While filtering, everything on a matching path is opened: a hit three
      // levels down is worthless if the reader has to guess where it is.
      const open = filtering || expanded.has(node.id);

      out.push({ node, indent, expandable: children.length > 0, expanded: open });
      if (!open) return;
      for (const child of children) walk(child, indent + 1);
    };

    for (const node of nodes) walk(node, 0);
    return out;
  }, [nodes, expanded, filtering, keep]);

  const toggle = (id: string) => {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const expandAll = () => {
    const all = new Set<string>();
    const walk = (node: DependencyTreeNode): void => {
      all.add(node.id);
      for (const child of node.children) walk(child);
    };
    for (const node of nodes) walk(node);
    setExpanded(all);
  };

  if (nodes.length === 0) {
    return (
      <EmptyState
        icon={Layers}
        title="No dependency graph yet"
        description="Upload this project's lockfile and every package it resolves to appears here, with a verdict on each one."
      />
    );
  }

  const visible = rows.slice(0, limit);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Input
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setLimit(RENDER_BUDGET);
          }}
          placeholder="Filter packages…"
          aria-label="Filter the dependency tree by package name"
          className="w-full sm:w-64"
        />

        <div className="flex items-center gap-2">
          <Switch
            id="flagged-only"
            checked={flaggedOnly}
            onCheckedChange={(checked) => {
              setFlaggedOnly(checked);
              setLimit(RENDER_BUDGET);
            }}
          />
          <Label htmlFor="flagged-only" className="text-sm font-normal">
            Flagged only
            <span className="font-mono text-xs text-muted-foreground">({flaggedCount})</span>
          </Label>
        </div>

        <div className="flex items-center gap-2 sm:ml-auto">
          <Button type="button" variant="outline" size="sm" onClick={expandAll}>
            Expand all
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => setExpanded(new Set())}
            disabled={filtering}
          >
            Collapse all
          </Button>
        </div>
      </div>

      {rows.length === 0 ? (
        <EmptyState
          size="sm"
          icon={ShieldAlert}
          title={
            flaggedOnly ? 'Nothing in this graph is flagged' : 'No package matches that filter'
          }
          description={
            flaggedOnly
              ? 'Every analysed dependency came back low risk or clean. Unanalysed packages are not ruled out — they are simply unknown.'
              : undefined
          }
        />
      ) : (
        <>
          <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border">
            {visible.map(({ node, indent, expandable, expanded: isOpen }) => (
              <li key={node.id}>
                <div
                  className="flex items-center gap-2 px-2 py-2 hover:bg-muted/40 sm:px-3"
                  style={{ paddingLeft: `${0.5 + Math.min(indent, 12) * 1.1}rem` }}
                >
                  {expandable ? (
                    <button
                      type="button"
                      onClick={() => toggle(node.id)}
                      aria-expanded={isOpen}
                      aria-label={`${isOpen ? 'Collapse' : 'Expand'} ${node.name}`}
                      className="flex size-5 shrink-0 items-center justify-center rounded text-muted-foreground hover:bg-muted hover:text-foreground"
                    >
                      {isOpen ? (
                        <ChevronDown aria-hidden="true" className="size-4" />
                      ) : (
                        <ChevronRight aria-hidden="true" className="size-4" />
                      )}
                    </button>
                  ) : (
                    <span aria-hidden="true" className="size-5 shrink-0" />
                  )}

                  <PackageRef
                    name={node.name}
                    version={node.version}
                    ecosystem={ecosystemSlug(node.ecosystem)}
                    href={versionHref(node.ecosystem, node.name, node.version)}
                    size="sm"
                    hideEcosystem
                    className="min-w-0"
                  />

                  {node.isDirect ? (
                    <Badge variant="outline" className="hidden shrink-0 text-[10px] sm:inline-flex">
                      direct
                    </Badge>
                  ) : null}

                  {node.quarantined ? (
                    <Badge variant="destructive" className="shrink-0 text-[10px]">
                      held
                    </Badge>
                  ) : null}

                  <div className="ml-auto flex shrink-0 items-center gap-2">
                    {!isOpen &&
                    expandable &&
                    node.subtreeWorst &&
                    node.subtreeWorst !== node.verdict ? (
                      <span
                        className={cn(
                          'hidden font-mono text-[10px] text-muted-foreground sm:inline',
                        )}
                        title={`Worst verdict inside this subtree: ${VERDICT_META[node.subtreeWorst].label}`}
                      >
                        ↓ {VERDICT_META[node.subtreeWorst].label}
                      </span>
                    ) : null}

                    {node.verdict ? (
                      <VerdictBadge verdict={node.verdict} size="sm" />
                    ) : (
                      <span className="text-xs text-muted-foreground">Not analysed</span>
                    )}
                  </div>
                </div>
              </li>
            ))}
          </ul>

          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-xs text-muted-foreground">
              Showing{' '}
              <span className="font-mono tabular-nums">
                {visible.length.toLocaleString('en-GB')}
              </span>{' '}
              of{' '}
              <span className="font-mono tabular-nums">{rows.length.toLocaleString('en-GB')}</span>{' '}
              visible rows. Collapsed subtrees are not counted.
            </p>
            {rows.length > visible.length ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setLimit((current) => current + RENDER_BUDGET)}
              >
                Show {Math.min(RENDER_BUDGET, rows.length - visible.length)} more
              </Button>
            ) : null}
          </div>
        </>
      )}

      <p className="text-xs text-muted-foreground">
        The tree is the shortest path to each package: a package reached by several routes appears
        once, under the shallowest parent.{' '}
        <Link href="/how-it-works" className="underline underline-offset-2">
          How the graph is built
        </Link>
        .
      </p>
    </div>
  );
}
