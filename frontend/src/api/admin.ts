import { apiFetch } from "@/api/client";
import type { ResetResponse } from "@/types/api";

export const adminApi = {
  resetPipeline(): Promise<ResetResponse> {
    return apiFetch<ResetResponse>(`/api/v1/admin/reset`, {
      method: "POST",
      body: JSON.stringify({ confirm: "RESET" }),
    });
  },
};
