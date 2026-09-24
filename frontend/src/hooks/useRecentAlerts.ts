import { useQuery } from "@tanstack/react-query";
import { alertsApi } from "@/api/alerts";

export function useRecentAlerts(limit = 5) {
  return useQuery({
    queryKey: ["alerts", "recent", limit],
    queryFn: () => alertsApi.listAlerts({ page: 1, page_size: limit, sort_by: "detected_at", sort_order: "desc" }),
    staleTime: 30 * 1000,
    retry: 1,
    select: (data) => data.items,
  });
}