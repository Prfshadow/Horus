export type HealthResponse = {
  status: string;
  app: string;
  env: string;
  database: string;
};

export type ApiError = {
  status: number;
  message: string;
  details?: unknown;
};

export type Event = {
  id: number;
  timestamp: string;
  ingested_at: string;
  source: string;
  level: string;
  service?: string | null;
  host?: string | null;
  message: string;
  raw_log: string;
  extra_data?: Record<string, unknown> | null;
};

export type Alert = {
  id: number;
  rule_id: number;
  rule_name: string;
  status: string;
  severity: string;
  detected_at: string;
  summary: string;
  context: Record<string, unknown>;
  first_event_id: number;
  last_event_id: number;
  evidence_event_ids: number[];
  created_at: string;
  updated_at: string;
};

export type Incident = {
  id: number;
  title: string;
  status: string;
  severity: string;
  correlation_key: string;
  context: Record<string, unknown>;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
  alert_ids: number[];
};

export type StatsResponse = {
  events: { total: number };
  alerts: {
    total: number;
    active: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
  };
  incidents: {
    total: number;
    open: number;
    investigating: number;
    resolved: number;
    by_severity: Record<string, number>;
  };
  generated_at: string;
};

export type PaginatedEventResponse = {
  items: Event[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
};

export type EventQueryParams = {
  page?: number;
  page_size?: number;
  search?: string;
  level?: string;
  source?: string;
  service?: string;
  host?: string;
  start_time?: string;
  end_time?: string;
  sort_by?: string;
  sort_order?: "asc" | "desc";
};

export type IngestResult = {
  index: number;
  event_id?: number | null;
  status: "stored" | "parse_error" | "system_error";
  error?: string | null;
};

export type IngestResponse = {
  accepted: number;
  failed: number;
  results: IngestResult[];
};

export type ResetResponse = {
  events_deleted: number;
  alerts_deleted: number;
  incidents_deleted: number;
  alert_events_deleted: number;
  incident_alerts_deleted: number;
};

export type PaginatedIncidentResponse = {
  items: Incident[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
};

export type IncidentQueryParams = {
  page?: number;
  page_size?: number;
  status?: string;
  severity?: string;
  search?: string;
  start_time?: string;
  end_time?: string;
  sort_by?: string;
  sort_order?: "asc" | "desc";
};

export type InvestigationIncident = {
  id: number;
  title: string;
  status: string;
  severity: string;
  correlation_key: string;
  context: Record<string, unknown>;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
};

export type InvestigationAlert = {
  id: number;
  rule_id: number;
  rule_name: string;
  rule_type?: string | null;
  severity: string;
  status: string;
  detected_at: string;
  summary: string;
  context: Record<string, unknown>;
  first_event_id: number;
  last_event_id: number;
  evidence_event_ids: number[];
};

export type InvestigationEvent = {
  id: number;
  timestamp: string;
  ingested_at: string;
  source: string;
  level: string;
  service?: string | null;
  host?: string | null;
  message: string;
  raw_log: string;
  extra_data?: Record<string, unknown> | null;
};

export type TimelineEntry = {
  type: "event" | "alert";
  id: number;
  timestamp: string;
  summary: string;
};

export type InvestigationCorrelation = {
  strategy: string;
  correlation_key: string;
  correlation_window_seconds: number;
};

export type InvestigationSummary = {
  alert_count: number;
  event_count: number;
  unique_sources: number;
  unique_hosts: number;
  unique_services: number;
  severity_breakdown: Record<string, number>;
  time_span_seconds: number;
  total_alert_count: number;
  total_event_count: number;
  truncated: boolean;
};

export type InvestigationEntities = {
  ips: string[];
  hosts: string[];
  services: string[];
  sources: string[];
};

export type InvestigationDetection = {
  alert_id: number;
  rule_id: number;
  rule_name: string;
  rule_type?: string | null;
  severity: string;
  summary: string;
  context: Record<string, unknown>;
};

export type InvestigationContextResponse = {
  incident: InvestigationIncident;
  alerts: InvestigationAlert[];
  events: InvestigationEvent[];
  timeline: TimelineEntry[];
  correlation: InvestigationCorrelation;
  summary: InvestigationSummary;
  entities: InvestigationEntities;
  detection: InvestigationDetection[];
};

export type AIObservation = {
  statement: string;
  type: "fact" | "inference" | "uncertainty";
  evidence_ids: string[];
  confidence?: "low" | "medium" | "high" | null;
};

export type AIAlternativeExplanation = {
  explanation: string;
  evidence_ids: string[];
};

export type AIProvenance = {
  provider: string;
  model: string;
  prompt_version: string;
  schema_version: string;
  incident_id: number;
  evidence_ids_used: string[];
  truncated: boolean;
  created_at: string;
};

export type AIInvestigationAnalysis = {
  summary: string;
  observations: AIObservation[];
  supporting_evidence: string[];
  alternative_explanations: AIAlternativeExplanation[];
  recommended_steps: string[];
  limitations: string[];
  provenance: AIProvenance | null;
};

export type AIInvestigationEvidenceMeta = {
  alerts_used: number;
  events_used: number;
  truncated: boolean;
  total_alerts: number;
  total_events: number;
};

export type AIInvestigateResponse = {
  incident_id: number;
  analysis: AIInvestigationAnalysis;
  evidence_meta: AIInvestigationEvidenceMeta;
  provenance: AIProvenance;
};
