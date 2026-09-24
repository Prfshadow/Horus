import { useQuery } from "@tanstack/react-query";
import { incidentsApi } from "@/api/incidents";

export function useRecentIncidents(limit = 5) {
  return useQuery({
    queryKey: ["incidents", "recent", limit],
    queryFn: () => incidentsApi.listIncidents({ page: 1, page_size: limit, sort_by: "last_seen_at", sort_order: "desc" }),
    staleTime: 30 * 1000,
    retry: 1,
  });
}
