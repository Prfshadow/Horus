import * as React from "react";
import { Link, useNavigate } from "react-router-dom";
import { Search, RefreshCw, X, ChevronLeft, ChevronRight, Filter } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { useEvents } from "@/hooks/useEvents";
import { formatDateTime } from "@/utils/formatDate";
import { getSeverityColor } from "@/utils/severity";
import type { EventQueryParams } from "@/types/api";

const LEVELS = ["", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"];
const SORT_FIELDS = ["timestamp", "ingested_at", "id", "level", "source"] as const;

export function EventsPage() {
  const navigate = useNavigate();
  const [search, setSearch] = React.useState("");
  const [level, setLevel] = React.useState("");
  const [source, setSource] = React.useState("");
  const [service, setService] = React.useState("");
  const [host, setHost] = React.useState("");
  const [startTime, setStartTime] = React.useState("");
  const [endTime, setEndTime] = React.useState("");
  const [sortBy, setSortBy] = React.useState<string>("timestamp");
  const [sortOrder, setSortOrder] = React.useState<"asc" | "desc">("desc");
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(50);

  // Debounce search
  const [debouncedSearch, setDebouncedSearch] = React.useState(search);
  React.useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search), 400);
    return () => clearTimeout(t);
  }, [search]);

  // Reset page when filters change
  React.useEffect(() => {
    setPage(1);
  }, [debouncedSearch, level, source, service, host, startTime, endTime, sortBy, sortOrder, pageSize]);

  const queryParams: EventQueryParams = {
    page,
    page_size: pageSize,
    search: debouncedSearch || undefined,
    level: level || undefined,
    source: source || undefined,
    service: service || undefined,
    host: host || undefined,
    start_time: startTime || undefined,
    end_time: endTime || undefined,
    sort_by: sortBy,
    sort_order: sortOrder,
  };

  const { data, isLoading, isError, error, refetch, isFetching } = useEvents(queryParams);

  const hasActiveFilters = !!(debouncedSearch || level || source || service || host || startTime || endTime);
  const clearFilters = () => {
    setSearch("");
    setLevel("");
    setSource("");
    setService("");
    setHost("");
    setStartTime("");
    setEndTime("");
  };

  const total = data?.total ?? 0;
  const totalPages = data?.total_pages ?? 1;
  const items = data?.items ?? [];

  return (
    <div className="hzc-section-gap">
      {/* Page Header */}
      <div className="hzc-page-head">
        <div>
          <p className="hzc-kicker">Event telemetry</p>
          <h1 className="hzc-title">EVENT EXPLORER</h1>
          <p className="hzc-subtitle">Normalized events — search, filter, sort and inspect evidence. Server-side querying.</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()} aria-label="Refresh events" className="hz-btn hz-btn-outline hz-btn-sm">
          <RefreshCw className="mr-2 h-4 w-4" /> Refresh
        </Button>
      </div>

      {/* Search & Filter Bar */}
      <div className="hzc-panel hzc-corners">
        <div className="hzc-panel-body" style={{ padding: "1rem" }}>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center" style={{ gap: "1rem" }}>
            <div className="relative flex-1 min-w-0">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" aria-hidden="true" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search message, source, service, host…"
                className="hz-input pl-9 pr-9"
                aria-label="Search events"
              />
              {search && (
                <button
                  onClick={() => setSearch("")}
                  className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-slate-400 hover:text-slate-200"
                  aria-label="Clear search"
                >
                  <X className="h-4 w-4" />
                </button>
              )}
            </div>
            <div className="flex items-center gap-2">
              <span className="hz-body-sm text-slate-500">{isFetching ? "Updating…" : `${total} results`}</span>
              {hasActiveFilters && (
                <Button variant="ghost" size="sm" onClick={clearFilters} className="hz-btn hz-btn-ghost hz-btn-sm">
                  <X className="mr-1 h-3 w-3" /> Clear filters
                </Button>
              )}
            </div>
          </div>

          {/* Advanced Filters */}
          <details className="mt-4" style={{ borderTop: "1px solid var(--hz-line)", paddingTop: "1rem" }}>
            <summary className="flex items-center gap-2 hz-kicker cursor-pointer list-none">
              <Filter className="h-4 w-4" aria-hidden="true" />
              Filters
              {hasActiveFilters && <span className="badge hz-badge-info text-xs">Active</span>}
            </summary>
            <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <label className="hz-field-label">Level</label>
                <select
                  value={level}
                  onChange={(e) => setLevel(e.target.value)}
                  className="hz-select"
                  aria-label="Filter by level"
                >
                  <option value="">All levels</option>
                  {LEVELS.filter(Boolean).map((l) => (
                    <option key={l} value={l}>{l}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="hz-field-label">Source</label>
                <input
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  placeholder="auth-service"
                  className="hz-input"
                  aria-label="Filter by source"
                />
              </div>
              <div>
                <label className="hz-field-label">Service</label>
                <input
                  value={service}
                  onChange={(e) => setService(e.target.value)}
                  placeholder="auth"
                  className="hz-input"
                  aria-label="Filter by service"
                />
              </div>
              <div>
                <label className="hz-field-label">Host</label>
                <input
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  placeholder="web-01"
                  className="hz-input"
                  aria-label="Filter by host"
                />
              </div>
              <div>
                <label className="hz-field-label">Start time (UTC)</label>
                <input
                  type="datetime-local"
                  value={startTime}
                  onChange={(e) => setStartTime(e.target.value ? new Date(e.target.value).toISOString() : "")}
                  className="hz-input"
                  aria-label="Filter start time"
                />
              </div>
              <div>
                <label className="hz-field-label">End time (UTC)</label>
                <input
                  type="datetime-local"
                  value={endTime}
                  onChange={(e) => setEndTime(e.target.value ? new Date(e.target.value).toISOString() : "")}
                  className="hz-input"
                  aria-label="Filter end time"
                />
              </div>
            </div>
            <div className="mt-4 flex flex-wrap items-center gap-3" style={{ borderTop: "1px solid var(--hz-line)", paddingTop: "1rem" }}>
              <div className="flex items-center gap-2">
                <label className="hz-body-sm text-slate-400">Sort by</label>
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value)}
                  className="hz-select w-auto"
                  aria-label="Sort by"
                >
                  {SORT_FIELDS.map((f) => (
                    <option key={f} value={f}>{f}</option>
                  ))}
                </select>
              </div>
              <div className="flex items-center gap-2">
                <label className="hz-body-sm text-slate-400">Order</label>
                <select
                  value={sortOrder}
                  onChange={(e) => setSortOrder(e.target.value as "asc" | "desc")}
                  className="hz-select w-auto"
                  aria-label="Sort order"
                >
                  <option value="desc">desc</option>
                  <option value="asc">asc</option>
                </select>
              </div>
              <div className="ml-auto flex items-center gap-2">
                <label className="hz-body-sm text-slate-400">Page size</label>
                <select
                  value={pageSize}
                  onChange={(e) => setPageSize(Number(e.target.value))}
                  className="hz-select w-auto"
                  aria-label="Page size"
                >
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </div>
            </div>
          </details>
        </div>
      </div>

      {/* Toolbar */}
      <div className="flex items-center justify-between hz-body-sm text-slate-400">
        <span>{total} {total === 1 ? "event" : "events"} • Page {data?.page ?? page} of {totalPages}</span>
        {hasActiveFilters && <span className="text-sky-400">Filters active</span>}
      </div>

      {/* Table */}
      <div className="hzc-panel hzc-corners">
        <div className="hzc-panel-body" style={{ padding: 0 }}>
          {isLoading ? (
            <div className="space-y-2 p-4" aria-busy="true">
              <div className="h-10 w-full bg-slate-800 rounded animate-pulse" />
              <div className="h-10 w-full bg-slate-800 rounded animate-pulse" />
              <div className="h-10 w-full bg-slate-800 rounded animate-pulse" />
              <div className="h-10 w-full bg-slate-800 rounded animate-pulse" />
            </div>
          ) : isError ? (
            <div className="p-6 text-center hzc-error-box">
              <p className="text-sm text-red-300">Unable to load events. Backend may be unavailable.</p>
              <Button variant="outline" size="sm" className="mt-3" onClick={() => refetch()}>
                Retry
              </Button>
              <p className="mt-2 hz-body-sm text-slate-500">{String((error as unknown as { message?: string })?.message ?? error)}</p>
            </div>
          ) : items.length === 0 ? (
            <div className="p-8 text-center">
              <p className="hz-body font-medium text-slate-200">
                {hasActiveFilters || debouncedSearch ? "No events match the current filters." : "No events yet."}
              </p>
              <p className="mt-1 hz-body-sm text-slate-500">
                {hasActiveFilters || debouncedSearch ? "Try adjusting search or filters." : "Ingest logs to see normalized events here."}
              </p>
              {(hasActiveFilters || debouncedSearch) && (
                <Button variant="outline" size="sm" onClick={clearFilters} className="hz-btn hz-btn-outline hz-btn-sm mt-3">
                  Clear filters
                </Button>
              )}
            </div>
          ) : (
            <div className="hzc-table-wrap">
              <table className="hzc-table" role="table">
                <thead>
                  <tr>
                    <th scope="col">Timestamp</th>
                    <th scope="col">Level</th>
                    <th scope="col">Source</th>
                    <th scope="col" className="hidden lg:table-cell">Service</th>
                    <th scope="col" className="hidden lg:table-cell">Host</th>
                    <th scope="col">Message</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((ev) => (
                    <tr
                      key={ev.id}
                      onClick={() => navigate(`/events/${ev.id}`)}
                      className="cursor-pointer"
                      tabIndex={0}
                      role="button"
                      aria-label={`View event ${ev.id}`}
                      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") navigate(`/events/${ev.id}`); }}
                    >
                      <td className="whitespace-nowrap hz-font-mono text-xs text-slate-400" title={formatDateTime(ev.timestamp)}>{formatDateTime(ev.timestamp)}</td>
                      <td><span className={`inline-flex rounded border px-2 py-0.5 text-xs font-medium hz-font-mono ${getSeverityColor(ev.level)}`}>{ev.level}</span></td>
                      <td className="max-w-[14ch] truncate hz-font-mono text-xs text-slate-300" title={ev.source}>{ev.source}</td>
                      <td className="hidden lg:table-cell max-w-[12ch] truncate text-xs text-slate-400" title={ev.service ?? ""}>{ev.service ?? "—"}</td>
                      <td className="hidden lg:table-cell max-w-[12ch] truncate text-xs text-slate-400" title={ev.host ?? ""}>{ev.host ?? "—"}</td>
                      <td className="max-w-[40ch] truncate text-sm text-slate-200" title={ev.message}>{ev.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Pagination */}
      {total > 0 && (
        <div className="flex flex-col items-center justify-between gap-3 sm:flex-row hz-body-sm">
          <span className="text-slate-400">
            Showing {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}
          </span>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1 || isFetching}
              aria-label="Previous page"
              className="hz-btn hz-btn-outline hz-btn-sm"
            >
              <ChevronLeft className="h-4 w-4" /> Prev
            </Button>
            <span className="text-slate-300">Page {page} of {totalPages}</span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages || isFetching}
              aria-label="Next page"
              className="hz-btn hz-btn-outline hz-btn-sm"
            >
              Next <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}

      <p className="text-center hz-body-sm text-slate-500 lg:hidden">Table scrolls horizontally on small screens. Tap a row to inspect.</p>
    </div>
  );
}