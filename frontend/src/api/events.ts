import { apiFetch } from "@/api/client";
import type { Event, EventQueryParams, IngestResponse, PaginatedEventResponse } from "@/types/api";

export const eventsApi = {
  listEvents(params?: EventQueryParams & { limit?: number }): Promise<PaginatedEventResponse> {
    const search = new URLSearchParams();
    // Backward compat: limit -> page_size
    if (params?.limit !== undefined && params?.page === undefined && params?.page_size === undefined) {
      search.set("page", "1");
      search.set("page_size", String(params.limit));
    } else {
      if (params?.page) search.set("page", String(params.page));
      if (params?.page_size) search.set("page_size", String(params.page_size));
      else if (params?.limit) search.set("page_size", String(params.limit));
    }
    if (params?.search) search.set("search", params.search);
    if (params?.level) search.set("level", params.level);
    if (params?.source) search.set("source", params.source);
    if (params?.service) search.set("service", params.service);
    if (params?.host) search.set("host", params.host);
    if (params?.start_time) search.set("start_time", params.start_time);
    if (params?.end_time) search.set("end_time", params.end_time);
    if (params?.sort_by) search.set("sort_by", params.sort_by);
    if (params?.sort_order) search.set("sort_order", params.sort_order);
    const qs = search.toString() ? `?${search.toString()}` : "";
    return apiFetch<PaginatedEventResponse>(`/api/v1/events${qs}`);
  },
  getEvent(id: number): Promise<Event> {
    return apiFetch<Event>(`/api/v1/events/${id}`);
  },
  ingestLogs(logs: string[], source?: string): Promise<IngestResponse> {
    return apiFetch<IngestResponse>(`/api/v1/ingest`, {
      method: "POST",
      body: JSON.stringify({ logs, source: source || undefined }),
    });
  },
};
