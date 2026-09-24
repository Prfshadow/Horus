import { useQuery } from "@tanstack/react-query";
import { investigationApi } from "@/api/investigation";
import type { InvestigationContextResponse } from "@/types/api";

export function useInvestigation(incidentId: number, params?: { include_events?: boolean; include_timeline?: boolean }) {
  return useQuery<InvestigationContextResponse>({
    queryKey: ["investigation", incidentId, params],
    queryFn: () => investigationApi.getInvestigation(incidentId, params),
    enabled: !!incidentId && incidentId > 0,
    staleTime: 30 * 1000,
    retry: 1,
  });
}