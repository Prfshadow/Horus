import { apiFetch } from "@/api/client";
import type { HealthResponse } from "@/types/api";

export const healthApi = {
  getHealth(): Promise<HealthResponse> {
    return apiFetch<HealthResponse>("/api/v1/health");
  },
};
