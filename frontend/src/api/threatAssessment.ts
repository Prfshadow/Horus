import { apiFetch } from "@/api/client";

export type ThreatLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type ThreatAssessmentRequest = {
  window_seconds?: number;
  correlation_window_seconds?: number;
  evaluation_time?: string;
  correlation_strategy?: "source_ip" | "host";
  rule_names?: string[];
  synthetic?: boolean;
  event_ids?: number[];
};

export type ThreatAssessmentResponse = {
  threat_level: ThreatLevel;
  threat_title: string;
  explanation: string;
  details: string[];
  alerts_count: number;
  incidents_count: number;
  events_analyzed: number;
  alert_severities: Record<string, number>;
  incident_severities: Record<string, number>;
  affected_entities: { ips: string[]; hosts: string[]; users: string[] };
  synthetic: boolean;
  alert_ids: number[];
  incident_ids: number[];
};

export const threatAssessmentApi = {
  assess(payload: ThreatAssessmentRequest = {}): Promise<ThreatAssessmentResponse> {
    return apiFetch<ThreatAssessmentResponse>("/api/v1/threat-assessment", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },
};
