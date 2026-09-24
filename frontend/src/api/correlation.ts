import { apiFetch } from "@/api/client";
import type { Incident } from "@/types/api";

export type CorrelateRequest = {
  window_seconds?: number;
  evaluation_time?: string;
  strategy?: "source_ip" | "host";
  rule_names?: string[];
};

export type CorrelateResponse = {
  window_seconds: number;
  evaluation_time: string;
  strategy: string;
  incidents_created: number;
  incidents_updated: number;
  alerts_correlated: number;
  incidents: Incident[];
};

export const correlationApi = {
  runCorrelation(payload: CorrelateRequest = {}): Promise<CorrelateResponse> {
    return apiFetch<CorrelateResponse>("/api/v1/correlate", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },
};