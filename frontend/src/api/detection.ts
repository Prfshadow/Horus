import { apiFetch } from "@/api/client";
import type { Alert } from "@/types/api";

export type DetectRequest = {
  window_seconds?: number;
  evaluation_time?: string;
  rule_names?: string[];
};

export type DetectResponse = {
  window_seconds: number;
  evaluation_time: string;
  alerts_created: number;
  alerts: Alert[];
};

export const detectionApi = {
  runDetection(payload: DetectRequest = {}): Promise<DetectResponse> {
    return apiFetch<DetectResponse>("/api/v1/detect", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },
};