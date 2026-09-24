import { useMutation } from "@tanstack/react-query";
import { investigationAiApi } from "@/api/investigationAi";
import type { AIInvestigateResponse } from "@/types/api";

export function useAIInvestigation(incidentId: number) {
  return useMutation<AIInvestigateResponse, Error, void>({
    mutationKey: ["ai-investigation", incidentId],
    mutationFn: () => investigationAiApi.investigateIncident(incidentId),
    retry: 0,
  });
}