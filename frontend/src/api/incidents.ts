import { apiFetch } from "@/api/client";
import type { Incident, PaginatedIncidentResponse, IncidentQueryParams } from "@/types/api";

export const incidentsApi = {
  listIncidents(params?: {
    page?: number;
    page_size?: number;
    status?: string;
    severity?: string;
    search?: string;
    start_time?: string;
    end_time?: string;
    sort_by?: string;
    sort_order?: "asc" | "desc";
  }): Promise<import("@/types/api").PaginatedIncidentResponse> {
    const search = new URLSearchParams();
    if (params?.page) search.set("page", String(params.page));
    if (params?.page_size) search.set("page_size", String(params.page_size));
    if (params?.status) search.set("status", params.status);
    if (params?.severity) search.set("severity", params.severity);
    if (params?.search) search.set("search", params.search);
    if (params?.start_time) search.set("start_time", params.start_time);
    if (params?.end_time) search.set("end_time", params.end_time);
    if (params?.sort_by) search.set("sort_by", params.sort_by);
    if (params?.sort_order) search.set("sort_order", params.sort_order);
    const qs = search.toString() ? `?${search.toString()}` : "";
    return apiFetch<import("@/types/api").PaginatedIncidentResponse>(`/api/v1/incidents${qs}`);
  },

  getIncident(id: number) {
    return apiFetch<Incident>(`/api/v1/incidents/${id}`);
  },
};
