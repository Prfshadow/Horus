import { apiFetch } from "@/api/client";
import type { StatsResponse } from "@/types/api";

export const statsApi = {
  getStats(): Promise<StatsResponse> {
    return apiFetch<StatsResponse>("/api/v1/stats");
  },
};
