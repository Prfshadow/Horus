import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { alertsApi } from "@/api/alerts";
import type { Alert } from "@/types/api";

export function useAlerts(params: {
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
}) {
  return useQuery({
    queryKey: ["alerts", params],
    queryFn: () => alertsApi.listAlerts(params),
    placeholderData: keepPreviousData,
    staleTime: 15 * 1000,
    retry: 1,
  });
}

export function useAlert(id: number) {
  return useQuery({
    queryKey: ["alerts", id],
    queryFn: () => alertsApi.getAlert(id),
    enabled: !!id,
    staleTime: 30 * 1000,
    retry: 1,
  });
}