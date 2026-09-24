import { apiFetch } from "@/api/client";
import type { InvestigationContextResponse } from "@/types/api";

export const investigationApi = {
  getInvestigation(incidentId: number, params?: { include_events?: boolean; include_timeline?: boolean }): Promise<InvestigationContextResponse> {
    const search = new URLSearchParams();
    if (params?.include_events !== undefined) search.set("include_events", String(params.include_events));
    if (params?.include_timeline !== undefined) search.set("include_timeline", String(params.include_timeline));
    const qs = search.toString() ? `?${search.toString()}` : "";
    return apiFetch<InvestigationContextResponse>(`/api/v1/incidents/${incidentId}/investigation${qs}`);
  },
};