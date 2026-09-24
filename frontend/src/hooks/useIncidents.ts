import { useMutation, useQuery, keepPreviousData } from "@tanstack/react-query";
import { incidentsApi } from "@/api/incidents";
import { detectionApi, type DetectRequest } from "@/api/detection";
import { correlationApi, type CorrelateRequest } from "@/api/correlation";
import type { IncidentQueryParams } from "@/types/api";

export function useIncidents(params: {
  page?: number;
  page_size?: number;
  status?: string;
  severity?: string;
  search?: string;
  start_time?: string;
  end_time?: string;
  sort_by?: string;
  sort_order?: "asc" | "desc";
}) {
  return useQuery({
    queryKey: ["incidents", params],
    queryFn: () => incidentsApi.listIncidents(params),
    placeholderData: keepPreviousData,
    staleTime: 15 * 1000,
    retry: 1,
  });
}

export function useIncident(id: number) {
  return useQuery({
    queryKey: ["incidents", id],
    queryFn: () => incidentsApi.getIncident(id),
    enabled: !!id,
    staleTime: 30 * 1000,
    retry: 1,
  });
}

export function useRunDetection() {
  return useMutation({
    mutationFn: (payload: DetectRequest = {}) => detectionApi.runDetection(payload),
    retry: 0,
  });
}

export function useRunCorrelation() {
  return useMutation({
    mutationFn: (payload: CorrelateRequest = {}) => correlationApi.runCorrelation(payload),
    retry: 0,
  });
}