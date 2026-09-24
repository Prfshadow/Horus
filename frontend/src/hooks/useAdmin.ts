import { useMutation } from "@tanstack/react-query";
import { adminApi } from "@/api/admin";
import type { ResetResponse } from "@/types/api";

export function useResetPipeline() {
  return useMutation<ResetResponse, Error, void>({
    mutationFn: () => adminApi.resetPipeline(),
    retry: 0,
  });
}
