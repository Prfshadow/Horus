import { useMutation, useQueryClient } from "@tanstack/react-query";
import { threatAssessmentApi, type ThreatAssessmentRequest } from "@/api/threatAssessment";

export function useThreatAssessment() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: ThreatAssessmentRequest = {}) => threatAssessmentApi.assess(payload),
    retry: 0,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["stats"] });
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["events"] });
    },
  });
}
