import { Link } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { Shield, Activity, Siren, Layers, ScrollText, AlertTriangle, Clock, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { useHealth } from "@/hooks/useHealth";
import { useStats } from "@/hooks/useStats";
import { useRecentAlerts } from "@/hooks/useRecentAlerts";
import { useRecentIncidents } from "@/hooks/useRecentIncidents";
import { useRecentEvents } from "@/hooks/useRecentEvents";
import { formatDateTime, formatRelative, formatLastUpdated } from "@/utils/formatDate";
import { getSeverityColor, getSeverityDot } from "@/utils/severity";
import { getStatusColor } from "@/utils/status";
import * as React from "react";

export function DashboardPage() {
  const queryClient = useQueryClient();
  const [lastUpdated, setLastUpdated] = React.useState<Date | null>(null);

  const health = useHealth();
  const stats = useStats();
  const alerts = useRecentAlerts(5);
  const incidents = useRecentIncidents(5);
  const events = useRecentEvents(5);

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ["stats"] });
    queryClient.invalidateQueries({ queryKey: ["alerts"] });
    queryClient.invalidateQueries({ queryKey: ["incidents"] });
    queryClient.invalidateQueries({ queryKey: ["events"] });
    queryClient.invalidateQueries({ queryKey: ["health"] });
    setLastUpdated(new Date());
  };

  React.useEffect(() => {
    if (stats.isSuccess || alerts.isSuccess || incidents.isSuccess) {
      if (!lastUpdated) setLastUpdated(new Date());
    }
  }, [stats.isSuccess, alerts.isSuccess, incidents.isSuccess, lastUpdated]);

  const statsData = stats.data;
  const alertsBySeverity = statsData?.alerts.by_severity ?? {};
  const incidentsBySeverity = statsData?.incidents.by_severity ?? {};
  const maxAlertSeverity = Math.max(...Object.values(alertsBySeverity), 1);
  const maxIncidentSeverity = Math.max(...Object.values(incidentsBySeverity), 1);

  return (
    <div className="hzc-section-gap">
      {/* Page Header */}
      <div className="hzc-page-head">
        <div>
          <p className="hzc-kicker">Command center</p>
          <h1 className="hzc-title">COMMAND CENTER</h1>
          <p className="hzc-subtitle">Security Operations Overview — deterministic, evidence-backed</p>
        </div>
        <div className="flex items-center gap-2">
          {lastUpdated && (
            <span className="hz-body-sm hidden sm:inline">
              Last updated {formatLastUpdated(lastUpdated)}
            </span>
          )}
          <Button variant="outline" size="sm" onClick={handleRefresh} aria-label="Refresh dashboard" className="hz-btn hz-btn-outline hz-btn-sm">
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
        </div>
      </div>

      {/* System Status */}
      <div className="hzc-panel hzc-corners">
        <div className="hzc-panel-head">
          <h3 className="hzc-panel-title">
            <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
            System Status
          </h3>
        </div>
        <div className="hzc-panel-body">
          <div className="hzc-metrics" role="list" aria-label="System health metrics">
            <div className="hzc-metric" role="listitem">
              <div className="flex items-center gap-2">
                <span className={`h-2 w-2 rounded-full ${health.data?.status === "ok" ? "bg-emerald-500" : health.isError ? "bg-red-500" : "bg-amber-500"}`} aria-hidden="true" />
                <span className="hzc-metric-label">HORUS Core</span>
              </div>
              <div className="hzc-metric-value">
                <span className={`badge ${health.isLoading ? "hz-badge-warning" : health.isError ? "hz-badge-error" : "hz-badge-success"}`}>
                  {health.isLoading ? "Checking…" : health.isError ? "Unavailable" : health.data?.status ?? "Unknown"}
                </span>
              </div>
            </div>
            <div className="hzc-metric" role="listitem">
              <div className="flex items-center gap-2">
                <span className={`h-2 w-2 rounded-full ${health.data?.database === "connected" ? "bg-emerald-500" : "bg-red-500"}`} aria-hidden="true" />
                <span className="hzc-metric-label">Database</span>
              </div>
              <div className="hzc-metric-value">
                <span className="hz-font-mono text-slate-300">{health.data?.database ?? "—"}</span>
              </div>
            </div>
            <div className="hzc-metric" role="listitem">
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-slate-500" aria-hidden="true" />
                <span className="hzc-metric-label">Generated</span>
              </div>
              <div className="hzc-metric-value">
                <span className="hz-font-mono text-slate-300">{stats.data?.generated_at ? formatDateTime(stats.data.generated_at) : "—"}</span>
              </div>
            </div>
            <div className="hzc-metric" role="listitem">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-slate-500" aria-hidden="true" />
                <span className="hzc-metric-label">Uptime</span>
              </div>
              <div className="hzc-metric-value">
                <span className="hz-font-mono text-slate-300">—</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Overview Stats */}
      <div className="hzc-metrics" role="list" aria-label="Overview statistics">
        <Link to="/events" className="hzc-metric" role="listitem">
          <div className="hzc-metric-label">Events</div>
          <div className="hzc-metric-value hz-data">{statsData?.events.total ?? 0}</div>
          <div className="hzc-metric-sub">All time — normalized events stored</div>
        </Link>
        <Link to="/alerts" className="hzc-metric" role="listitem">
          <div className="hzc-metric-label">Active Alerts</div>
          <div className="hzc-metric-value hz-data">{statsData?.alerts.active ?? 0}</div>
          <div className="hzc-metric-sub">Detected + acknowledged (all time)</div>
        </Link>
        <Link to="/incidents" className="hzc-metric" role="listitem">
          <div className="hzc-metric-label">Open Incidents</div>
          <div className="hzc-metric-value hz-data">{statsData?.incidents.open ?? 0}</div>
          <div className="hzc-metric-sub">Currently requiring investigation</div>
        </Link>
        <Link to="/incidents" className="hzc-metric" role="listitem">
          <div className="hzc-metric-label">Investigating</div>
          <div className="hzc-metric-value hz-data">{statsData?.incidents.investigating ?? 0}</div>
          <div className="hzc-metric-sub">Under active investigation</div>
        </Link>
      </div>

      {/* Threat Overview */}
      <div className="hzc-section-gap">
        <div className="hzc-panel hzc-corners">
          <div className="hzc-panel-head">
            <h3 className="hzc-panel-title">
              <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <path d="M9 12l2 2 4-4" />
              </svg>
              Threat Overview
            </h3>
          </div>
          <div className="hzc-panel-body">
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <p className="hz-kicker mb-3">Alert Severity</p>
                {stats.isLoading ? (
                  <div className="space-y-3" aria-busy="true">
                    <div className="h-6 bg-slate-800 rounded animate-pulse" />
                    <div className="h-6 bg-slate-800 rounded animate-pulse" />
                    <div className="h-6 bg-slate-800 rounded animate-pulse" />
                    <div className="h-6 bg-slate-800 rounded animate-pulse" />
                  </div>
                ) : stats.isError ? (
                  <p className="hz-body-sm text-red-300">Unable to load severity.</p>
                ) : Object.keys(alertsBySeverity).length === 0 ? (
                  <p className="hz-body-sm text-slate-500">No alerts yet.</p>
                ) : (
                  <div className="space-y-3" role="list" aria-label="Alert severity distribution">
                    {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                      <div key={sev} className="hzc-meter" role="listitem">
                        <span className={`hzc-meter-label hzc-sevtext-${sev}`}>{sev}</span>
                        <div className="hzc-meter-track">
                          <div className={`hzc-meter-fill hzc-sev-${sev}`} style={{ width: `${maxAlertSeverity > 0 ? (alertsBySeverity[sev] ?? 0) / maxAlertSeverity * 100 : 0}%` }} />
                        </div>
                        <span className="hzc-meter-count hz-font-mono">{alertsBySeverity[sev] ?? 0}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
              <div>
                <p className="hz-kicker mb-3">Incident Severity</p>
                {stats.isLoading ? (
                  <div className="space-y-3" aria-busy="true">
                    <div className="h-6 bg-slate-800 rounded animate-pulse" />
                    <div className="h-6 bg-slate-800 rounded animate-pulse" />
                    <div className="h-6 bg-slate-800 rounded animate-pulse" />
                    <div className="h-6 bg-slate-800 rounded animate-pulse" />
                  </div>
                ) : stats.isError ? (
                  <p className="hz-body-sm text-red-300">Unable to load severity.</p>
                ) : Object.keys(incidentsBySeverity).length === 0 ? (
                  <p className="hz-body-sm text-slate-500">No incidents yet.</p>
                ) : (
                  <div className="space-y-3" role="list" aria-label="Incident severity distribution">
                    {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                      <div key={sev} className="hzc-meter" role="listitem">
                        <span className={`hzc-meter-label hzc-sevtext-${sev}`}>{sev}</span>
                        <div className="hzc-meter-track">
                          <div className={`hzc-meter-fill hzc-sev-${sev}`} style={{ width: `${maxIncidentSeverity > 0 ? (incidentsBySeverity[sev] ?? 0) / maxIncidentSeverity * 100 : 0}%` }} />
                        </div>
                        <span className="hzc-meter-count hz-font-mono">{incidentsBySeverity[sev] ?? 0}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Alerts / Incidents */}
      <div className="hzc-section-gap" style={{ display: "grid", gap: "1rem", gridTemplateColumns: "repeat(auto-fit, minmax(400px, 1fr))" }}>
        {/* Recent Alerts */}
        <div className="hzc-panel hzc-corners">
          <div className="hzc-panel-head">
            <h3 className="hzc-panel-title">
              <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
                <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
                <path d="M13.73 21a2 2 0 0 1-3.46 0" />
              </svg>
              Recent Alerts
            </h3>
            <Link to="/alerts" className="hz-body-sm text-sky-400 hover:text-sky-300">View all</Link>
          </div>
          <div className="hzc-panel-body">
            {alerts.isLoading ? (
              <div className="space-y-2" aria-busy="true">
                <div className="h-10 bg-slate-800 rounded animate-pulse" />
                <div className="h-10 bg-slate-800 rounded animate-pulse" />
                <div className="h-10 bg-slate-800 rounded animate-pulse" />
              </div>
            ) : alerts.isError ? (
              <div className="hzc-error-box">
                <p>Unable to load alerts. Backend may be unavailable.</p>
                <Button variant="outline" size="sm" className="mt-3" onClick={() => alerts.refetch()}>
                  Retry
                </Button>
              </div>
            ) : alerts.data?.length === 0 ? (
              <p className="hzc-empty">No alerts yet.</p>
            ) : (
              <div className="space-y-2" role="list">
                {alerts.data?.map((a) => (
                  <Link
                    key={a.id}
                    to={`/alerts/${a.id}`}
                    className="hzc-row"
                    role="listitem"
                  >
                    <span className={`h-2 w-2 rounded-full ${getSeverityDot(a.severity)}`} aria-hidden="true" />
                    <span className={`badge ${getSeverityColor(a.severity)} text-xs`}>{a.severity}</span>
                    <span className="font-medium text-slate-200 truncate max-w-[20ch]">{a.rule_name}</span>
                    <span className="ml-auto flex items-center gap-2">
                      <span className={`badge ${getStatusColor(a.status)} text-xs`}>{a.status}</span>
                      <span className="hz-body-sm text-slate-400">{formatRelative(a.detected_at)}</span>
                    </span>
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Recent Incidents */}
        <div className="hzc-panel hzc-corners">
          <div className="hzc-panel-head">
            <h3 className="hzc-panel-title">
              <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
                <rect x="3" y="3" width="7" height="9" rx="1" />
                <rect x="14" y="3" width="7" height="5" rx="1" />
                <rect x="14" y="12" width="7" height="9" rx="1" />
                <rect x="3" y="16" width="7" height="5" rx="1" />
              </svg>
              Recent Incidents
            </h3>
            <Link to="/incidents" className="hz-body-sm text-sky-400 hover:text-sky-300">View all</Link>
          </div>
          <div className="hzc-panel-body">
            {incidents.isLoading ? (
              <div className="space-y-2" aria-busy="true">
                <div className="h-10 bg-slate-800 rounded animate-pulse" />
                <div className="h-10 bg-slate-800 rounded animate-pulse" />
                <div className="h-10 bg-slate-800 rounded animate-pulse" />
              </div>
            ) : incidents.isError ? (
              <div className="hzc-error-box">
                <p>Unable to load incidents. Backend may be unavailable.</p>
                <Button variant="outline" size="sm" className="mt-3" onClick={() => incidents.refetch()}>
                  Retry
                </Button>
              </div>
            ) : incidents.data?.items?.length === 0 ? (
              <p className="hzc-empty">No incidents yet.</p>
            ) : (
              <div className="space-y-2" role="list">
                {incidents.data?.items?.map((inc) => (
                  <Link
                    key={inc.id}
                    to={`/incidents/${inc.id}`}
                    className="hzc-row"
                    role="listitem"
                  >
                    <div className="flex items-center justify-between w-full">
                      <span className="font-medium text-slate-200 truncate max-w-[20ch]">{inc.title}</span>
                      <span className={`badge ${getStatusColor(inc.status)} text-xs shrink-0`}>{inc.status}</span>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-slate-400 mt-1">
                      <span className={`badge ${getSeverityColor(inc.severity)} text-xs`}>{inc.severity}</span>
                      <span className="hz-font-mono text-sky-400 truncate max-w-[16ch]">{inc.correlation_key}</span>
                      <span className="ml-auto">{formatRelative(inc.last_seen_at)}</span>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="hzc-panel hzc-corners">
        <div className="hzc-panel-head">
          <h3 className="hzc-panel-title">
            <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
              <polyline points="4 18 4 6 20 6" />
              <line x1="4" y1="6" x2="20" y2="6" />
            </svg>
            Recent Activity
          </h3>
          <Link to="/events" className="hz-body-sm text-sky-400 hover:text-sky-300">View all</Link>
        </div>
        <div className="hzc-panel-body">
          {events.isLoading ? (
            <div className="space-y-2" aria-busy="true">
              <div className="h-10 bg-slate-800 rounded animate-pulse" />
              <div className="h-10 bg-slate-800 rounded animate-pulse" />
              <div className="h-10 bg-slate-800 rounded animate-pulse" />
            </div>
          ) : events.isError ? (
            <div className="hzc-error-box">
              <p>Unable to load events. Backend may be unavailable.</p>
              <Button variant="outline" size="sm" className="mt-3" onClick={() => events.refetch()}>
                Retry
              </Button>
            </div>
          ) : events.data?.items?.length === 0 ? (
            <p className="hzc-empty">No events yet.</p>
          ) : (
            <div className="hzc-table-wrap">
              <table className="hzc-table" role="table">
                <thead>
                  <tr>
                    <th scope="col">Timestamp</th>
                    <th scope="col">Level</th>
                    <th scope="col">Source</th>
                    <th scope="col" className="hidden lg:table-cell">Service</th>
                    <th scope="col" className="hidden lg:table-cell">Host</th>
                    <th scope="col">Message</th>
                  </tr>
                </thead>
                <tbody>
                  {events.data?.items?.map((ev) => (
                    <tr key={ev.id} onClick={() => window.location.href = `/events/${ev.id}`} className="cursor-pointer" tabIndex={0} role="button" aria-label={`View event ${ev.id}`} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") window.location.href = `/events/${ev.id}`; }}>
                      <td className="whitespace-nowrap hz-font-mono text-xs text-slate-400" title={formatDateTime(ev.timestamp)}>{formatDateTime(ev.timestamp)}</td>
                      <td><span className={`inline-flex rounded border px-2 py-0.5 text-xs font-medium hz-font-mono ${getSeverityColor(ev.level)}`}>{ev.level}</span></td>
                      <td className="max-w-[14ch] truncate hz-font-mono text-xs text-slate-300" title={ev.source}>{ev.source}</td>
                      <td className="hidden lg:table-cell max-w-[12ch] truncate text-xs text-slate-400" title={ev.service ?? ""}>{ev.service ?? "—"}</td>
                      <td className="hidden lg:table-cell max-w-[12ch] truncate text-xs text-slate-400" title={ev.host ?? ""}>{ev.host ?? "—"}</td>
                      <td className="max-w-[40ch] truncate text-sm text-slate-200" title={ev.message}>{ev.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Footer note */}
      <p className="text-center hz-body-sm">
        All metrics are deterministic and derived from HORUS backend aggregates. No fake security scores. Generated at{" "}
        {stats.data?.generated_at ? formatDateTime(stats.data.generated_at) : "—"}.
      </p>
    </div>
  );
}