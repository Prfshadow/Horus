import { apiFetch } from "@/api/client";
import type { AIInvestigateResponse } from "@/types/api";

export const investigationAiApi = {
  investigateIncident(incidentId: number): Promise<AIInvestigateResponse> {
    return apiFetch<AIInvestigateResponse>(`/api/v1/incidents/${incidentId}/investigate`, {
      method: "POST",
      body: JSON.stringify({}),
    });
  },
};