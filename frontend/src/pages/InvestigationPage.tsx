import * as React from "react";
import { Link, useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, Search, AlertTriangle, Shield, Network, Server, User, Hash, Clock, ChevronDown, ChevronUp, Copy, Check, Brain } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { useInvestigation } from "@/hooks/useInvestigation";
import { useAIInvestigation } from "@/hooks/useAIInvestigation";
import { AiInvestigationPanel } from "@/components/ai/AiInvestigationPanel";
import { formatDateTime } from "@/utils/formatDate";
import { getSeverityColor } from "@/utils/severity";
import { getStatusColor } from "@/utils/status";
import type { TimelineEntry } from "@/types/api";

function JsonBlock({ data, maxHeight = "max-h-64" }: { data: unknown; maxHeight?: string }) {
  if (data == null || (typeof data === "object" && Object.keys(data as Record<string, unknown>).length === 0)) {
    return <p className="hz-body-sm text-slate-500">No structured data.</p>;
  }
  let pretty: string;
  try {
    pretty = JSON.stringify(data, null, 2);
  } catch {
    pretty = String(data);
  }
  return (
    <pre className={`${maxHeight} overflow-auto rounded-md border border-slate-700 bg-slate-900 p-3 hz-font-mono text-xs text-slate-200`}>
      <code>{pretty}</code>
    </pre>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = React.useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // ignore
    }
  };
  return (
    <Button variant="ghost" size="sm" onClick={onCopy} aria-label="Copy" className="hz-btn hz-btn-ghost hz-btn-sm">
      {copied ? <Check className="h-4 w-4 text-emerald-500" /> : <Copy className="h-4 w-4" />}
      <span className="ml-1 hz-body-sm">{copied ? "Copied" : "Copy"}</span>
    </Button>
  );
}

function EvidenceChip({ type, id }: { type: "alert" | "event"; id: number }) {
  const Icon = type === "alert" ? AlertTriangle : Search;
  const color = "";
  const bg = type === "alert" ? "hz-neon-warning" : "hz-neon-info";
  const route = type === "alert" ? `/alerts/${id}` : `/events/${id}`;
  const label = type === "alert" ? `Alert #${id}` : `Event #${id}`;

  return (
    <Link
      to={route}
      className={`inline-flex items-center gap-1 rounded border px-2 py-1 hz-font-mono text-xs ${color} ${bg} hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500`}
      aria-label={`View ${label}`}
    >
      <Icon className="h-3 w-3" />
      {type === "alert" ? "alert:" : "event:"}{id}
    </Link>
  );
}

function EntityChips({ entities, label, icon: Icon, color, bg }: { entities: string[]; label: string; icon: React.ElementType; color: string; bg: string }) {
  if (!entities || entities.length === 0) return null;
  return (
    <div className="space-y-2">
      <dt className="flex items-center gap-1 hz-body-sm font-medium text-slate-400">
        <Icon className="h-3 w-3" /> {label}
      </dt>
      <dd className="flex flex-wrap gap-1.5">
        {entities.map((entity, idx) => (
          <span
            key={`${label}-${idx}`}
            className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 hz-font-mono text-xs ${color} ${bg}`}
          >
            {entity}
          </span>
        ))}
      </dd>
    </div>
  );
}

function CollapsibleSection({ title, children, icon: Icon, defaultOpen = true }: { title: string; children: React.ReactNode; icon?: React.ElementType; defaultOpen?: boolean }) {
  const [open, setOpen] = React.useState(defaultOpen);
  return (
    <div className="hzc-panel hzc-corners">
      <div className="hzc-panel-head">
        <h3 className="hzc-panel-title flex items-center gap-2">
          {Icon && <Icon className="h-4 w-4" />}
          {title}
        </h3>
        <Button variant="ghost" size="icon" onClick={() => setOpen(!open)} aria-label={open ? `Collapse ${title}` : `Expand ${title}`} aria-expanded={open} className="hz-btn hz-btn-ghost hz-btn-sm">
          {open ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
        </Button>
      </div>
      {open && <div className="hzc-panel-body">{children}</div>}
    </div>
  );
}

function TimelineItem({ entry, index }: { entry: TimelineEntry; index: number }) {
  const isAlert = entry.type === "alert";
  const dotColor = isAlert ? "bg-amber-500" : "bg-sky-500";

  return (
    <div className="relative pl-6 pb-6">
      <div className="absolute left-0 top-1 h-full w-0.5 bg-slate-700" style={{ opacity: index === 0 ? 0 : 1 }} />
      <div className="relative flex items-start gap-3">
        <div className={`relative flex-shrink-0 h-3 w-3 rounded-full ${dotColor} border-2 border-slate-900`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 hz-body-sm">
            <span className="hz-font-mono text-slate-400" title={entry.timestamp}>{formatDateTime(entry.timestamp)}</span>
            <span className={`badge ${isAlert ? "hz-badge-warning" : "hz-badge-info"} text-xs`}>{entry.type.toUpperCase()}</span>
            <span className="hz-font-mono text-slate-500">#{entry.id}</span>
          </div>
          <p className="mt-1 hz-body text-slate-300 break-words">{entry.summary}</p>
        </div>
      </div>
    </div>
  );
}

function TruncationBanner({ truncated, totalAlerts, totalEvents, totalTimeline }: { truncated?: boolean; totalAlerts?: number; totalEvents?: number; totalTimeline?: number }) {
  if (!truncated) return null;
  return (
    <div className="hzc-panel hzc-corners border-amber-700/50 bg-amber-950/30">
      <div className="hzc-panel-body">
        <div className="flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 flex-shrink-0 text-amber-400" />
          <span className="text-amber-200">Evidence was truncated for investigation context.</span>
        </div>
        <div className="mt-2 grid gap-1 sm:grid-cols-3 hz-body-sm text-amber-300">
          {totalAlerts !== undefined && <span>Total alerts: <strong>{totalAlerts}</strong></span>}
          {totalEvents !== undefined && <span>Total events: <strong>{totalEvents}</strong></span>}
          {totalTimeline !== undefined && <span>Total timeline entries: <strong>{totalTimeline}</strong></span>}
        </div>
      </div>
    </div>
  );
}

export function InvestigationPage() {
  const { id } = useParams<{ id: string }>();
  const incidentId = Number(id);
  const isValidId = Number.isInteger(incidentId) && incidentId > 0;
  const navigate = useNavigate();

  const { data: investigation, isLoading, isError, error, refetch } = useInvestigation(isValidId ? incidentId : 0, {
    include_events: true,
    include_timeline: true,
  });

  const aiInvestigation = useAIInvestigation(incidentId);

  if (!isValidId) {
    return (
      <div className="hzc-section-gap">
        <Link to="/incidents" className="inline-flex items-center hz-body-sm text-sky-400 hover:text-sky-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 rounded">
          <ArrowLeft className="mr-1 h-4 w-4" /> Back to Incidents
        </Link>
        <div className="hzc-panel hzc-corners mt-4">
          <div className="hzc-panel-body p-8 text-center">
            <p className="hz-body font-medium text-slate-200">Invalid incident ID.</p>
            <p className="mt-1 hz-body-sm text-slate-500">Expected a positive integer.</p>
          </div>
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="hzc-section-gap space-y-6">
        <div className="flex items-center gap-4">
          <div className="h-8 w-48 bg-slate-800 rounded animate-pulse" />
          <div className="h-6 w-32 bg-slate-800 rounded animate-pulse" />
        </div>
        <div className="h-32 w-full bg-slate-800 rounded animate-pulse" />
        <div className="h-48 w-full bg-slate-800 rounded animate-pulse" />
        <div className="h-64 w-full bg-slate-800 rounded animate-pulse" />
        <div className="h-48 w-full bg-slate-800 rounded animate-pulse" />
        <div className="h-48 w-full bg-slate-800 rounded animate-pulse" />
      </div>
    );
  }

  if (isError) {
    const isNotFound = (error as unknown as { status?: number })?.status === 404;
    return (
      <div className="hzc-section-gap">
        <Link to="/incidents" className="inline-flex items-center hz-body-sm text-sky-400 hover:text-sky-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 rounded">
          <ArrowLeft className="mr-1 h-4 w-4" /> Back to Incidents
        </Link>
        <div className="hzc-panel hzc-corners mt-4">
          <div className="hzc-panel-body p-8 text-center">
            <p className="hz-body font-medium text-slate-200">{isNotFound ? "Investigation not found." : "Unable to load investigation."}</p>
            <p className="mt-1 hz-body-sm text-slate-500">{isNotFound ? `No investigation for incident ${incidentId}.` : String((error as unknown as { message?: string })?.message ?? error)}</p>
            <Button variant="outline" size="sm" onClick={() => refetch()} className="hz-btn hz-btn-outline hz-btn-sm mt-4">
              Retry
            </Button>
          </div>
        </div>
      </div>
    );
  }

  if (!investigation) {
    return (
      <div className="hzc-section-gap">
        <Link to="/incidents" className="inline-flex items-center hz-body-sm text-sky-400 hover:text-sky-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 rounded">
          <ArrowLeft className="mr-1 h-4 w-4" /> Back to Incidents
        </Link>
        <div className="hzc-panel hzc-corners mt-4">
          <div className="hzc-panel-body p-8 text-center">
            <p className="hz-body-sm text-slate-500">No investigation data.</p>
          </div>
        </div>
      </div>
    );
  }

  const { incident, alerts, events, timeline, correlation, summary, entities, detection } = investigation;
  const truncated = summary.truncated;

  return (
    <div className="hzc-section-gap">
      {/* Breadcrumb / Back to Incident */}
      <Link to={`/incidents/${incidentId}`} className="inline-flex items-center hz-body-sm text-sky-400 hover:text-sky-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 rounded">
        <ArrowLeft className="mr-1 h-4 w-4" /> Back to Incident
      </Link>

      {/* Incident Header */}
      <div className="hzc-panel hzc-corners">
        <div className="hzc-panel-body space-y-4">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <h1 className="hzc-title" style={{ fontSize: "clamp(1.25rem, 2.4vw, 1.75rem)" }}>{incident.title}</h1>
              <p className="hz-body-sm text-slate-400">Deterministic Investigation — evidence-backed, bounded context.</p>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`badge ${getSeverityColor(incident.severity)}`}>{incident.severity}</span>
              <span className={`badge ${getStatusColor(incident.status)}`}>{incident.status}</span>
            </div>
          </div>

          <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5 hz-body-sm">
            <div className="flex flex-col gap-1">
              <dt className="text-slate-400">Incident ID</dt>
              <dd className="hz-font-mono text-slate-200">{incident.id}</dd>
            </div>
            <div className="flex flex-col gap-1">
              <dt className="text-slate-400">Correlation Key</dt>
              <dd className="hz-font-mono text-sky-400 truncate max-w-xs" title={incident.correlation_key}>{incident.correlation_key}</dd>
            </div>
            <div className="flex flex-col gap-1">
              <dt className="text-slate-400">First Seen</dt>
              <dd className="text-slate-200" title={incident.first_seen_at}>{formatDateTime(incident.first_seen_at)}</dd>
            </div>
            <div className="flex flex-col gap-1">
              <dt className="text-slate-400">Last Seen</dt>
              <dd className="text-slate-200" title={incident.last_seen_at}>{formatDateTime(incident.last_seen_at)}</dd>
            </div>
            <div className="flex flex-col gap-1">
              <dt className="text-slate-400">Time Span</dt>
              <dd className="hz-font-mono text-slate-200">{summary.time_span_seconds}s</dd>
            </div>
          </dl>
        </div>
      </div>

      {/* Truncation Banner */}
      <TruncationBanner
        truncated={truncated}
        totalAlerts={summary.total_alert_count}
        totalEvents={summary.total_event_count}
      />

      {/* Investigation Summary */}
      <CollapsibleSection title="Investigation Summary" icon={Shield} defaultOpen={true}>
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 hz-body-sm">
            <div className="p-3 rounded border border-slate-700 bg-slate-900/50">
              <dt className="text-slate-400">Alerts</dt>
              <dd className="text-2xl font-semibold text-slate-100">{summary.alert_count}</dd>
            </div>
            <div className="p-3 rounded border border-slate-700 bg-slate-900/50">
              <dt className="text-slate-400">Events</dt>
              <dd className="text-2xl font-semibold text-slate-100">{summary.event_count}</dd>
            </div>
            <div className="p-3 rounded border border-slate-700 bg-slate-900/50">
              <dt className="text-slate-400">Unique Sources</dt>
              <dd className="text-2xl font-semibold text-slate-100">{summary.unique_sources}</dd>
            </div>
            <div className="p-3 rounded border border-slate-700 bg-slate-900/50">
              <dt className="text-slate-400">Unique Hosts</dt>
              <dd className="text-2xl font-semibold text-slate-100">{summary.unique_hosts}</dd>
            </div>
            <div className="p-3 rounded border border-slate-700 bg-slate-900/50 sm:col-span-2">
              <dt className="text-slate-400">Unique Services</dt>
              <dd className="text-2xl font-semibold text-slate-100">{summary.unique_services}</dd>
            </div>
            <div className="p-3 rounded border border-slate-700 bg-slate-900/50 sm:col-span-2">
              <dt className="text-slate-400">Severity Breakdown</dt>
              <dd className="flex flex-wrap gap-1.5">
                {Object.entries(summary.severity_breakdown).map(([sev, count]) => (
                  <span key={sev} className={`badge ${getSeverityColor(sev)}`}>{sev}: {count}</span>
                ))}
              </dd>
            </div>
          </div>

          {/* Entities */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <EntityChips entities={entities.ips} label="IP Addresses" icon={Network} color="" bg="hz-neon-info" />
            <EntityChips entities={entities.hosts} label="Hosts" icon={Server} color="" bg="hz-neon-success" />
            <EntityChips entities={entities.services} label="Services" icon={Shield} color="" bg="hz-neon-warning" />
            <EntityChips entities={entities.sources} label="Sources" icon={Hash} color="" bg="hz-neon-violet" />
          </div>
        </div>
      </CollapsibleSection>

      {/* Detection & Correlation */}
      <div className="grid gap-4 lg:grid-cols-2">
        <CollapsibleSection title="Correlation" icon={Network} defaultOpen={true}>
          <dl className="space-y-2 hz-body-sm">
            <div className="flex justify-between gap-4">
              <dt className="text-slate-400">Strategy</dt>
              <dd className="hz-font-mono text-slate-200 text-right">{correlation.strategy}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-400">Correlation Key</dt>
              <dd className="hz-font-mono text-sky-400 text-right truncate max-w-xs" title={correlation.correlation_key}>{correlation.correlation_key}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-400">Window</dt>
              <dd className="hz-font-mono text-slate-200 text-right">{correlation.correlation_window_seconds}s</dd>
            </div>
          </dl>
        </CollapsibleSection>

        <CollapsibleSection title="Detection Rules" icon={Shield} defaultOpen={true}>
          {detection.length === 0 ? (
            <p className="hz-body-sm text-slate-500">No detection information available.</p>
          ) : (
            <div className="space-y-3">
              {detection.map((det, idx) => (
                <div key={`${det.alert_id}-${idx}`} className="hzc-panel hzc-corners p-3" style={{ borderColor: "var(--hz-line)" }}>
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="font-medium text-slate-200">{det.rule_name}</span>
                    <div className="flex items-center gap-2">
                      <span className={`badge ${getSeverityColor(det.severity)}`}>{det.severity}</span>
                      {det.rule_type && <span className="badge hz-badge-info text-xs">{det.rule_type}</span>}
                    </div>
                  </div>
                  <p className="hz-body text-slate-300 mb-2">{det.summary}</p>
                  <div className="flex gap-2">
                    <Link to={`/alerts/${det.alert_id}`}>
                      <Button variant="outline" size="sm" className="hz-btn hz-btn-outline hz-btn-sm">View Alert</Button>
                    </Link>
                    {det.context && Object.keys(det.context).length > 0 && (
                      <Link to={`/alerts/${det.alert_id}`}>
                        <Button variant="ghost" size="sm" className="hz-btn hz-btn-ghost hz-btn-sm">View Context</Button>
                      </Link>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CollapsibleSection>
      </div>

      {/* Timeline */}
      <CollapsibleSection title="Unified Timeline" icon={Clock} defaultOpen={true}>
        {timeline.length === 0 ? (
          <p className="hz-body-sm text-slate-500">No timeline entries available.</p>
        ) : (
          <div className="space-y-0">
            {timeline.map((entry, idx) => (
              <TimelineItem key={`${entry.type}-${entry.id}-${idx}`} entry={entry} index={idx} />
            ))}
          </div>
        )}
      </CollapsibleSection>

      {/* Alerts */}
      <CollapsibleSection title={`Alerts (${alerts.length})`} icon={AlertTriangle} defaultOpen={true}>
        {alerts.length === 0 ? (
          <p className="hz-body-sm text-slate-500">No alerts in this investigation.</p>
        ) : (
          <div className="space-y-3">
            {alerts.map((alert) => (
              <div key={alert.id} className="hzc-panel hzc-corners p-4" style={{ borderColor: "var(--hz-line)" }}>
                <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                  <div className="flex items-center gap-3 flex-wrap">
                    <Link to={`/alerts/${alert.id}`} className="font-medium text-sky-400 hover:text-sky-300">
                      {alert.rule_name}
                    </Link>
                    <span className={`badge ${getSeverityColor(alert.severity)}`}>{alert.severity}</span>
                    <span className={`badge ${getStatusColor(alert.status)}`}>{alert.status}</span>
                    <span className="hz-font-mono hz-body-sm text-slate-400" title={alert.detected_at}>{formatDateTime(alert.detected_at)}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Link to={`/alerts/${alert.id}`}>
                      <Button variant="outline" size="sm" className="hz-btn hz-btn-outline hz-btn-sm">View Alert</Button>
                    </Link>
                    {alert.evidence_event_ids.length > 0 && (
                      <span className="flex items-center gap-1 hz-font-mono text-xs text-slate-400">
                        Evidence: {alert.evidence_event_ids.map((eid, i) => (
                          <EvidenceChip key={i} type="event" id={eid} />
                        ))}
                      </span>
                    )}
                  </div>
                </div>
                <p className="mt-2 hz-body text-slate-300">{alert.summary}</p>
                {alert.context && Object.keys(alert.context).length > 0 && (
                  <details className="mt-2 group">
                    <summary className="flex items-center gap-1 hz-body-sm text-slate-400 cursor-pointer hover:text-slate-200 list-none">
                      <ChevronDown className="h-3 w-3 transition-transform group-open:rotate-180" />
                      Show Context
                    </summary>
                    <JsonBlock data={alert.context} maxHeight="max-h-48" />
                  </details>
                )}
              </div>
            ))}
          </div>
        )}
      </CollapsibleSection>

      {/* Events */}
      <CollapsibleSection title={`Evidence Events (${events.length})`} icon={Search} defaultOpen={false}>
        {events.length === 0 ? (
          <p className="hz-body-sm text-slate-500">No evidence events in this investigation.</p>
        ) : (
          <div className="space-y-3">
            {events.map((event) => (
              <div key={event.id} className="hzc-panel hzc-corners p-4" style={{ borderColor: "var(--hz-line)" }}>
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex items-center gap-3 flex-wrap">
                    <Link to={`/events/${event.id}`} className="hz-font-mono text-sky-400 hover:text-sky-300">
                      Event #{event.id}
                    </Link>
                    <span className={`badge ${getSeverityColor(event.level)}`}>{event.level}</span>
                    <span className="hz-font-mono hz-body-sm text-slate-400" title={event.timestamp}>{formatDateTime(event.timestamp)}</span>
                    <span className="hz-font-mono hz-body-sm text-slate-500">{event.source}</span>
                    {event.service && <span className="hz-body-sm text-slate-500">{event.service}</span>}
                    {event.host && <span className="hz-body-sm text-slate-500">{event.host}</span>}
                  </div>
                  <Link to={`/events/${event.id}`}>
                    <Button variant="outline" size="sm" className="hz-btn hz-btn-outline hz-btn-sm">View Event</Button>
                  </Link>
                </div>
                <p className="mt-2 hz-body text-slate-300 break-words">{event.message}</p>
                {(event.raw_log && event.raw_log !== event.message) && (
                  <details className="mt-2 group">
                    <summary className="flex items-center gap-1 hz-body-sm text-slate-400 cursor-pointer hover:text-slate-200 list-none">
                      <ChevronDown className="h-3 w-3 transition-transform group-open:rotate-180" />
                      Show Raw Log
                    </summary>
                    <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-words rounded-md border border-slate-700 bg-slate-900 p-3 hz-font-mono text-xs text-slate-200">
                      <code>{event.raw_log}</code>
                    </pre>
                  </details>
                )}
                {event.extra_data && Object.keys(event.extra_data).length > 0 && (
                  <details className="mt-2 group">
                    <summary className="flex items-center gap-1 hz-body-sm text-slate-400 cursor-pointer hover:text-slate-200 list-none">
                      <ChevronDown className="h-3 w-3 transition-transform group-open:rotate-180" />
                      Show Extra Data
                    </summary>
                    <JsonBlock data={event.extra_data} maxHeight="max-h-48" />
                  </details>
                )}
              </div>
            ))}
          </div>
        )}
      </CollapsibleSection>

      {/* AI Investigation */}
      <AiInvestigationPanel
        incidentId={incidentId}
        onInvestigate={() => aiInvestigation.mutate()}
        isLoading={aiInvestigation.isPending}
        isError={aiInvestigation.isError}
        error={aiInvestigation.error}
        data={aiInvestigation.data ?? null}
        isIdle={aiInvestigation.isIdle}
        reset={aiInvestigation.reset}
      />
    </div>
  );
}