import { useQuery } from "@tanstack/react-query";
import { eventsApi } from "@/api/events";
import type { PaginatedEventResponse } from "@/types/api";

export function useRecentEvents(limit = 5) {
  return useQuery<PaginatedEventResponse>({
    queryKey: ["events", "recent", limit],
    queryFn: () => eventsApi.listEvents({ limit }),
    staleTime: 30 * 1000,
    retry: 1,
  });
}
