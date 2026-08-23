'use client';

import { useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Search,
  X,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { LoadingSkeleton } from '@/components/shared/LoadingSkeleton';
import { cn } from '@/lib/utils';

export type SortDirection = 'asc' | 'desc';

export interface DataTableSort {
  columnId: string;
  direction: SortDirection;
}

export type SortableValue = string | number | boolean | Date | null | undefined;

export interface DataTableColumn<TRow> {
  /** Stable identifier, used for sort state and as the React key. */
  id: string;
  header: ReactNode;
  cell: (row: TRow) => ReactNode;
  /**
   * Value used for sorting. Providing it makes the column sortable; omit it for
   * columns that hold only actions or decoration.
   */
  sortValue?: (row: TRow) => SortableValue;
  /** Text contributed to the free-text search index. Defaults to `sortValue`. */
  searchValue?: (row: TRow) => string;
  align?: 'left' | 'center' | 'right';
  /** Applied to both the header cell and every body cell in the column. */
  className?: string;
  headerClassName?: string;
  /** Hide below the `sm` breakpoint to keep 360px viewports readable. */
  hideBelowSm?: boolean;
}

export interface DataTableFacet<TRow> {
  id: string;
  label: string;
  options: ReadonlyArray<{ value: string; label: string }>;
  /** Row's value(s) for this facet. A row matches if any value equals the selection. */
  accessor: (row: TRow) => string | string[] | null | undefined;
}

export interface DataTableProps<TRow> {
  data: readonly TRow[];
  columns: ReadonlyArray<DataTableColumn<TRow>>;
  getRowId: (row: TRow) => string;
  /** Show the free-text search box. */
  searchable?: boolean;
  searchPlaceholder?: string;
  /** Dropdown filters rendered next to the search box. */
  facets?: ReadonlyArray<DataTableFacet<TRow>>;
  initialSort?: DataTableSort;
  pageSize?: number;
  pageSizeOptions?: readonly number[];
  /** Rendered in place of the table body when there is nothing to show. */
  emptyState?: ReactNode;
  /** Rendered when a search or facet filters everything out. */
  noResultsState?: ReactNode;
  isLoading?: boolean;
  onRowClick?: (row: TRow) => void;
  /** Screen-reader description of the table's contents. */
  caption?: string;
  className?: string;
}

const ALL = '__all__';

function compareValues(a: SortableValue, b: SortableValue): number {
  const aEmpty = a === null || a === undefined || a === '';
  const bEmpty = b === null || b === undefined || b === '';
  if (aEmpty && bEmpty) return 0;
  // Missing values always sort last, in both directions.
  if (aEmpty) return 1;
  if (bEmpty) return -1;

  if (a instanceof Date && b instanceof Date) return a.getTime() - b.getTime();
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  if (typeof a === 'boolean' && typeof b === 'boolean') return Number(a) - Number(b);

  return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
}

function alignClass(align: DataTableColumn<unknown>['align']): string {
  if (align === 'right') return 'text-right';
  if (align === 'center') return 'text-center';
  return 'text-left';
}

/**
 * Generic table with client-side search, faceted filtering, sorting and
 * pagination.
 *
 * Client-side is the right call for the volumes this app puts in a table — a
 * page of scans, an org's API keys, the signals from one report. Anything
 * unbounded (the full scan history) is paginated in the service layer and
 * handed to this component one page at a time with `searchable={false}`.
 */
export function DataTable<TRow>({
  data,
  columns,
  getRowId,
  searchable = true,
  searchPlaceholder = 'Search…',
  facets = [],
  initialSort,
  pageSize: initialPageSize = 25,
  pageSizeOptions = [10, 25, 50, 100],
  emptyState,
  noResultsState,
  isLoading = false,
  onRowClick,
  caption,
  className,
}: DataTableProps<TRow>) {
  const [query, setQuery] = useState('');
  const [facetValues, setFacetValues] = useState<Record<string, string>>({});
  const [sort, setSort] = useState<DataTableSort | null>(initialSort ?? null);
  const [pageSize, setPageSize] = useState(initialPageSize);
  const [pageIndex, setPageIndex] = useState(0);

  const activeFacetCount = Object.values(facetValues).filter((v) => v && v !== ALL).length;
  const hasFilters = query.trim().length > 0 || activeFacetCount > 0;

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();

    return data.filter((row) => {
      for (const facet of facets) {
        const selected = facetValues[facet.id];
        if (!selected || selected === ALL) continue;
        const rowValue = facet.accessor(row);
        const values = Array.isArray(rowValue) ? rowValue : [rowValue];
        if (!values.some((value) => value === selected)) return false;
      }

      if (!needle) return true;

      return columns.some((column) => {
        if (column.searchValue) {
          return column.searchValue(row).toLowerCase().includes(needle);
        }
        if (column.sortValue) {
          const value = column.sortValue(row);
          if (value === null || value === undefined) return false;
          return String(value).toLowerCase().includes(needle);
        }
        return false;
      });
    });
  }, [data, columns, facets, facetValues, query]);

  const sorted = useMemo(() => {
    if (!sort) return filtered;
    const column = columns.find((candidate) => candidate.id === sort.columnId);
    if (!column?.sortValue) return filtered;

    const accessor = column.sortValue;
    const factor = sort.direction === 'asc' ? 1 : -1;
    return [...filtered].sort((a, b) => compareValues(accessor(a), accessor(b)) * factor);
  }, [filtered, columns, sort]);

  const pageCount = Math.max(1, Math.ceil(sorted.length / pageSize));

  // Filtering can shrink the result set out from under the current page.
  useEffect(() => {
    setPageIndex((current) => Math.min(current, pageCount - 1));
  }, [pageCount]);

  const pageRows = useMemo(() => {
    const start = pageIndex * pageSize;
    return sorted.slice(start, start + pageSize);
  }, [sorted, pageIndex, pageSize]);

  function toggleSort(column: DataTableColumn<TRow>) {
    if (!column.sortValue) return;
    setPageIndex(0);
    setSort((current) => {
      if (!current || current.columnId !== column.id) {
        return { columnId: column.id, direction: 'asc' };
      }
      if (current.direction === 'asc') {
        return { columnId: column.id, direction: 'desc' };
      }
      return null;
    });
  }

  function clearFilters() {
    setQuery('');
    setFacetValues({});
    setPageIndex(0);
  }

  const showToolbar = searchable || facets.length > 0;
  const rangeStart = sorted.length === 0 ? 0 : pageIndex * pageSize + 1;
  const rangeEnd = Math.min(sorted.length, (pageIndex + 1) * pageSize);

  return (
    <div className={cn('flex w-full flex-col gap-3', className)}>
      {showToolbar ? (
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-1 flex-col gap-2 sm:flex-row sm:items-center">
            {searchable ? (
              <div className="relative w-full sm:max-w-xs">
                <Search
                  aria-hidden="true"
                  className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
                />
                <Input
                  type="search"
                  value={query}
                  aria-label={searchPlaceholder}
                  placeholder={searchPlaceholder}
                  onChange={(event) => {
                    setQuery(event.target.value);
                    setPageIndex(0);
                  }}
                  className="pl-8"
                />
              </div>
            ) : null}

            {facets.map((facet) => (
              <Select
                key={facet.id}
                value={facetValues[facet.id] ?? ALL}
                onValueChange={(value) => {
                  setFacetValues((current) => ({ ...current, [facet.id]: value }));
                  setPageIndex(0);
                }}
              >
                <SelectTrigger className="w-full sm:w-[180px]" aria-label={facet.label}>
                  <SelectValue placeholder={facet.label} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={ALL}>All {facet.label.toLowerCase()}</SelectItem>
                  {facet.options.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ))}

            {hasFilters ? (
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                <X aria-hidden="true" />
                Clear
              </Button>
            ) : null}
          </div>

          <p className="shrink-0 font-mono text-xs text-muted-foreground tabular-nums">
            {sorted.length} {sorted.length === 1 ? 'row' : 'rows'}
          </p>
        </div>
      ) : null}

      {isLoading ? (
        <LoadingSkeleton variant="table" rows={Math.min(pageSize, 8)} />
      ) : data.length === 0 && emptyState ? (
        emptyState
      ) : (
        <>
          <div className="overflow-x-auto rounded-lg border border-border">
            <Table>
              {caption ? <caption className="sr-only">{caption}</caption> : null}
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  {columns.map((column) => {
                    const isSorted = sort?.columnId === column.id;
                    const sortable = Boolean(column.sortValue);
                    const SortIcon = !isSorted
                      ? ArrowUpDown
                      : sort?.direction === 'asc'
                        ? ArrowUp
                        : ArrowDown;

                    return (
                      <TableHead
                        key={column.id}
                        aria-sort={
                          isSorted
                            ? sort?.direction === 'asc'
                              ? 'ascending'
                              : 'descending'
                            : sortable
                              ? 'none'
                              : undefined
                        }
                        className={cn(
                          alignClass(column.align),
                          column.hideBelowSm && 'hidden sm:table-cell',
                          column.headerClassName,
                          column.className,
                        )}
                      >
                        {sortable ? (
                          <button
                            type="button"
                            onClick={() => toggleSort(column)}
                            className={cn(
                              '-mx-2 inline-flex items-center gap-1.5 rounded px-2 py-1 font-medium text-muted-foreground transition-colors hover:text-foreground',
                              isSorted && 'text-foreground',
                            )}
                          >
                            {column.header}
                            <SortIcon aria-hidden="true" className="size-3.5" />
                          </button>
                        ) : (
                          column.header
                        )}
                      </TableHead>
                    );
                  })}
                </TableRow>
              </TableHeader>

              <TableBody>
                {pageRows.length === 0 ? (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={columns.length} className="h-32 p-4">
                      {noResultsState ?? (
                        <p className="text-center text-sm text-muted-foreground">
                          No rows match the current filters.
                        </p>
                      )}
                    </TableCell>
                  </TableRow>
                ) : (
                  pageRows.map((row) => (
                    <TableRow
                      key={getRowId(row)}
                      onClick={onRowClick ? () => onRowClick(row) : undefined}
                      tabIndex={onRowClick ? 0 : undefined}
                      onKeyDown={
                        onRowClick
                          ? (event) => {
                              if (event.key === 'Enter' || event.key === ' ') {
                                event.preventDefault();
                                onRowClick(row);
                              }
                            }
                          : undefined
                      }
                      className={cn(onRowClick && 'cursor-pointer focus-visible:bg-accent/60')}
                    >
                      {columns.map((column) => (
                        <TableCell
                          key={column.id}
                          className={cn(
                            alignClass(column.align),
                            column.hideBelowSm && 'hidden sm:table-cell',
                            column.className,
                          )}
                        >
                          {column.cell(row)}
                        </TableCell>
                      ))}
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          <div className="flex flex-col-reverse items-center justify-between gap-3 sm:flex-row">
            <p className="font-mono text-xs text-muted-foreground tabular-nums">
              {rangeStart}–{rangeEnd} of {sorted.length}
            </p>

            <div className="flex items-center gap-2">
              <Select
                value={String(pageSize)}
                onValueChange={(value) => {
                  setPageSize(Number(value));
                  setPageIndex(0);
                }}
              >
                <SelectTrigger size="sm" className="w-[110px]" aria-label="Rows per page">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {pageSizeOptions.map((option) => (
                    <SelectItem key={option} value={String(option)}>
                      {option} / page
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <nav aria-label="Pagination" className="flex items-center gap-1">
                <Button
                  variant="outline"
                  size="icon"
                  aria-label="First page"
                  disabled={pageIndex === 0}
                  onClick={() => setPageIndex(0)}
                >
                  <ChevronsLeft aria-hidden="true" />
                </Button>
                <Button
                  variant="outline"
                  size="icon"
                  aria-label="Previous page"
                  disabled={pageIndex === 0}
                  onClick={() => setPageIndex((current) => Math.max(0, current - 1))}
                >
                  <ChevronLeft aria-hidden="true" />
                </Button>
                <span className="px-2 font-mono text-xs text-muted-foreground tabular-nums">
                  {pageIndex + 1} / {pageCount}
                </span>
                <Button
                  variant="outline"
                  size="icon"
                  aria-label="Next page"
                  disabled={pageIndex >= pageCount - 1}
                  onClick={() => setPageIndex((current) => Math.min(pageCount - 1, current + 1))}
                >
                  <ChevronRight aria-hidden="true" />
                </Button>
                <Button
                  variant="outline"
                  size="icon"
                  aria-label="Last page"
                  disabled={pageIndex >= pageCount - 1}
                  onClick={() => setPageIndex(pageCount - 1)}
                >
                  <ChevronsRight aria-hidden="true" />
                </Button>
              </nav>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
