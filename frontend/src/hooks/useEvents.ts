import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { eventsApi } from "@/api/events";
import type { EventQueryParams } from "@/types/api";

export function useEvents(params: EventQueryParams) {
  return useQuery({
    queryKey: ["events", params],
    queryFn: () => eventsApi.listEvents(params),
    placeholderData: keepPreviousData,
    staleTime: 15 * 1000,
    retry: 1,
  });
}

export function useEvent(id: number) {
  return useQuery({
    queryKey: ["events", id],
    queryFn: () => eventsApi.getEvent(id),
    enabled: !!id,
    staleTime: 30 * 1000,
    retry: 1,
  });
}
