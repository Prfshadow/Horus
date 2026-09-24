import { apiFetch } from "@/api/client";
import type { Alert } from "@/types/api";

export const alertsApi = {
  listAlerts(params?: {
    page?: number;
    page_size?: number;
    search?: string;
    status?: string;
    severity?: string;
    rule_name?: string;
    start_time?: string;
    end_time?: string;
    sort_by?: string;
    sort_order?: "asc" | "desc";
  }): Promise<{ items: Alert[]; page: number; page_size: number; total: number; total_pages: number }> {
    const search = new URLSearchParams();
    if (params?.page) search.set("page", String(params.page));
    if (params?.page_size) search.set("page_size", String(params.page_size));
    if (params?.search) search.set("search", params.search);
    if (params?.status) search.set("status", params.status);
    if (params?.severity) search.set("severity", params.severity);
    if (params?.rule_name) search.set("rule_name", params.rule_name);
    if (params?.start_time) search.set("start_time", params.start_time);
    if (params?.end_time) search.set("end_time", params.end_time);
    if (params?.sort_by) search.set("sort_by", params.sort_by);
    if (params?.sort_order) search.set("sort_order", params.sort_order);
    const qs = search.toString() ? `?${search.toString()}` : "";
    return apiFetch<{ items: Alert[]; page: number; page_size: number; total: number; total_pages: number }>(`/api/v1/alerts${qs}`);
  },

  getAlert(id: number): Promise<Alert> {
    return apiFetch<Alert>(`/api/v1/alerts/${id}`);
  },
};