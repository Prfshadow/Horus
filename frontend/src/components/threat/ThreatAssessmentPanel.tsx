import * as React from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, CheckCircle2, FlaskConical, Loader2, ShieldAlert } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import type { ThreatAssessmentResponse } from "@/api/threatAssessment";

const LEVEL_STYLE: Record<string, { badge: string; border: string; icon: string }> = {
  LOW: {
    badge: "hz-neon-low",
    border: "border-slate-700",
    icon: "🟢",
  },
  MEDIUM: {
    badge: "hz-neon-medium",
    border: "border-amber-800/60",
    icon: "🟡",
  },
  HIGH: {
    badge: "hz-neon-high",
    border: "border-orange-800/60",
    icon: "🔴",
  },
  CRITICAL: {
    badge: "hz-neon-critical",
    border: "border-red-800/60",
    icon: "🔴",
  },
};

const FALLBACK_STYLE = { badge: "hz-neon-default", border: "border-slate-700", icon: "⚪" };

function levelStyle(level: string): { badge: string; border: string; icon: string } {
  return LEVEL_STYLE[level] ?? FALLBACK_STYLE;
}

export function ThreatAssessmentPanel({
  assessment,
  assessing,
  error,
  eventsReceived,
  onAssess,
  assessLabel = "Assess recent events",
  showSyntheticWarning,
  incidentId,
}: {
  assessment: ThreatAssessmentResponse | null;
  assessing: boolean;
  error: string | null;
  eventsReceived?: number | null;
  onAssess: () => void;
  assessLabel?: string;
  showSyntheticWarning?: boolean;
  /** Optional deep-link target: precise incident from this assessment run. */
  incidentId?: number;
}) {
  const [showEvidence, setShowEvidence] = React.useState(false);

  return (
    <Card className="animate-fade-up border-cyan-800/40 bg-gradient-to-br from-slate-800/80 via-slate-800/70 to-cyan-950/30">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-cyan-400" /> Threat Assessment
        </CardTitle>
        <p className="text-xs text-slate-400">
          Runs the existing detection + correlation pipeline and summarizes what HORUS found. No manual rule
          knowledge required.
        </p>
      </CardHeader>
      <CardContent>
        <Button size="sm" onClick={onAssess} disabled={assessing} aria-busy={assessing}>
          {assessing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldAlert className="mr-2 h-4 w-4" />}
          {assessing ? "Assessing…" : assessLabel}
        </Button>

        {assessing && (
          <p className="mt-3 flex items-center gap-2 text-sm text-cyan-200" role="status" aria-live="polite">
            <Loader2 className="h-4 w-4 animate-spin" /> Analyzing ingested events through detection + correlation…
          </p>
        )}

        {error && (
          <div className="mt-3 rounded-md border border-red-800 bg-red-950/40 p-3 text-sm text-red-200" role="alert">
            <p>
              {eventsReceived != null && eventsReceived > 0
                ? `Logs stored successfully (${eventsReceived.toLocaleString()} events). `
                : ""}
              Threat assessment could not be completed{error ? `: ${error}` : "."}
            </p>
            <p className="mt-1 text-xs text-red-300/80">Use the button above to retry the analysis.</p>
          </div>
        )}

        {assessment && (
          <div className={`mt-4 space-y-4 rounded-md border bg-slate-900/60 p-4 ${levelStyle(assessment.threat_level).border}`} role="status">
            {(assessment.synthetic || showSyntheticWarning) && (
              <p className="flex items-center gap-2 rounded-md border border-violet-700 bg-violet-950/50 p-2 text-xs text-violet-200">
                <FlaskConical className="h-4 w-4" /> SYNTHETIC / DEMO DATA — NOT REAL SECURITY TELEMETRY
              </p>
            )}

            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm font-bold tracking-widest ${levelStyle(assessment.threat_level).badge}`}
              >
                <span aria-hidden="true">{levelStyle(assessment.threat_level).icon}</span>
                {assessment.threat_level} THREAT{assessment.alerts_count === 0 ? "" : " DETECTED"}
              </span>
            </div>

            <div>
              <h3 className="text-base font-semibold text-slate-100">{assessment.threat_title}</h3>
              <p className="mt-1 whitespace-pre-line text-sm text-slate-300">{assessment.explanation}</p>
            </div>

            {assessment.details.length > 0 && (
              <div className="rounded-md border border-slate-700 bg-slate-800/50 p-3">
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Why HORUS flagged this
                </p>
                <ul className="mt-2 space-y-1 text-sm text-slate-200">
                  {assessment.details.map((d, i) => (
                    <li key={i}>{d.startsWith("•") ? d : `• ${d}`}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="grid gap-2 sm:grid-cols-3">
              <div className="rounded-md border border-slate-700 bg-slate-800/50 p-3 text-center">
                <p className="text-xs text-slate-400">Events analyzed</p>
                <p className="font-mono text-xl text-slate-100">{assessment.events_analyzed.toLocaleString()}</p>
              </div>
              <div className="rounded-md border border-slate-700 bg-slate-800/50 p-3 text-center">
                <p className="text-xs text-slate-400">Alerts</p>
                <p className="font-mono text-xl text-slate-100">{assessment.alerts_count.toLocaleString()}</p>
              </div>
              <div className="rounded-md border border-slate-700 bg-slate-800/50 p-3 text-center">
                <p className="text-xs text-slate-400">Incidents</p>
                <p className="font-mono text-xl text-slate-100">{assessment.incidents_count.toLocaleString()}</p>
              </div>
            </div>

            {(assessment.affected_entities.ips.length > 0 ||
              assessment.affected_entities.hosts.length > 0 ||
              assessment.affected_entities.users.length > 0) && (
              <div className="text-xs text-slate-400">
                {assessment.affected_entities.hosts.length > 0 && (
                  <p>
                    Affected host{assessment.affected_entities.hosts.length === 1 ? "" : "s"}:{" "}
                    <span className="font-mono text-slate-200">{assessment.affected_entities.hosts.join(", ")}</span>
                  </p>
                )}
                {assessment.affected_entities.ips.length > 0 && (
                  <p>
                    Source IP{assessment.affected_entities.ips.length === 1 ? "" : "s"}:{" "}
                    <span className="font-mono text-slate-200">{assessment.affected_entities.ips.join(", ")}</span>
                  </p>
                )}
                {assessment.affected_entities.users.length > 0 && (
                  <p>
                    Account{assessment.affected_entities.users.length === 1 ? "" : "s"}:{" "}
                    <span className="font-mono text-slate-200">{assessment.affected_entities.users.join(", ")}</span>
                  </p>
                )}
              </div>
            )}

            {assessment.alerts_count === 0 && (
              <p className="flex items-center gap-2 text-sm text-emerald-200">
                <CheckCircle2 className="h-4 w-4" /> No configured threats detected in the analyzed events.
              </p>
            )}

            <div>
              <button
                type="button"
                onClick={() => setShowEvidence((v) => !v)}
                className="text-xs text-sky-400 hover:text-sky-300"
                aria-expanded={showEvidence}
              >
                {showEvidence ? "Hide technical evidence" : "Show technical evidence"}
              </button>
              {showEvidence && (
                <div className="mt-2 space-y-2 text-xs">
                  {Object.keys(assessment.alert_severities).length > 0 && (
                    <p className="text-slate-400">
                      Alerts by severity:{" "}
                      <span className="font-mono text-slate-200">
                        {Object.entries(assessment.alert_severities).map(([s, c]) => `${s}: ${c}`).join(" • ")}
                      </span>
                    </p>
                  )}
                  {Object.keys(assessment.incident_severities).length > 0 && (
                    <p className="text-slate-400">
                      Incidents by severity:{" "}
                      <span className="font-mono text-slate-200">
                        {Object.entries(assessment.incident_severities).map(([s, c]) => `${s}: ${c}`).join(" • ")}
                      </span>
                    </p>
                  )}
                </div>
              )}
            </div>

            <div className="flex flex-wrap gap-2">
              <Link
                to="/alerts"
                className="inline-flex items-center gap-1 rounded px-3 py-1.5 text-xs font-medium border hz-neon-success hover:opacity-80"
              >
                <AlertTriangle className="h-3 w-3" /> View Alerts
              </Link>
              {incidentId !== undefined ? (
                <>
                  <Link
                    to={`/incidents/${incidentId}`}
                    className="inline-flex items-center gap-1 rounded px-3 py-1.5 text-xs font-medium border hz-neon-info hover:opacity-80"
                  >
                    View Incident
                  </Link>
                  <Link
                    to={`/incidents/${incidentId}/investigation`}
                    className="inline-flex items-center gap-1 rounded px-3 py-1.5 text-xs font-medium border hz-neon-violet hover:opacity-80"
                  >
                    <FlaskConical className="h-3 w-3" /> Investigate
                  </Link>
                </>
              ) : (
                <>
                  <Link
                    to="/incidents"
                    className="inline-flex items-center gap-1 rounded px-3 py-1.5 text-xs font-medium border hz-neon-info hover:opacity-80"
                  >
                    View Incidents
                  </Link>
                  {assessment.incidents_count > 0 && (
                    <Link
                      to="/incidents"
                      className="inline-flex items-center gap-1 rounded px-3 py-1.5 text-xs font-medium border hz-neon-violet hover:opacity-80"
                    >
                      <FlaskConical className="h-3 w-3" /> Investigate
                    </Link>
                  )}
                </>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
