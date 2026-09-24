import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { FlaskConical, Loader2, Dices } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { ingestAllLines, useIngestLogs } from "@/hooks/useIngest";
import type { ThreatAssessmentResponse } from "@/api/threatAssessment";
import {
  SCENARIO_META,
  SCENARIO_ORDER,
  buildScenario,
  scenarioSourceIps,
  type ScenarioName,
} from "@/utils/syntheticScenarios";

const SCENARIO_BADGE: Record<string, string> = {
  authentication_attack: "hz-neon-high",
  network_reconnaissance: "hz-neon-info",
  web_application_attack: "hz-neon-warning",
  malware_detection: "hz-neon-error",
  privilege_escalation: "hz-neon-high",
  data_transfer_anomaly: "hz-neon-info",
  multi_stage_incident: "hz-neon-error",
  mostly_normal: "hz-neon-default",
};

/**
 * Synthetic Threat Lab — shared by /inject and /threat-lab.
 *
 * Generates clearly-marked synthetic telemetry and feeds it through the
 * REAL ingestion → detection → correlation pipeline. Nothing is faked:
 * `onAssessLab` runs the scoped threat assessment and the result is shown
 * by the caller's ThreatAssessmentPanel.
 */
export function ThreatLabPanel({
  onAssessLab,
  assessing,
}: {
  onAssessLab: (eventIds: number[]) => Promise<ThreatAssessmentResponse | null>;
  assessing: boolean;
}) {
  const queryClient = useQueryClient();
  const ingest = useIngestLogs();
  const [scenario, setScenario] = React.useState<ScenarioName>("multi_stage_incident");
  const [busy, setBusy] = React.useState(false);
  const [status, setStatus] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["stats"] });
    queryClient.invalidateQueries({ queryKey: ["events"] });
    queryClient.invalidateQueries({ queryKey: ["alerts"] });
    queryClient.invalidateQueries({ queryKey: ["incidents"] });
    queryClient.invalidateQueries({ queryKey: ["health"] });
  };

  const runLab = async () => {
    setError(null);
    setStatus(null);
    setBusy(true);
    try {
      const { name, lines } = buildScenario(scenario);
      const sources = scenarioSourceIps(lines);
      setStatus(`Generating ${SCENARIO_META[name].label}… (${lines.length} synthetic events)`);
      const summary = await ingestAllLines(
        lines,
        "synthetic-lab",
        (batch, src) => ingest.mutateAsync({ logs: batch, source: src }),
        (current, total) => setStatus(`Injecting synthetic batch ${current} of ${total}…`),
      );
      if (summary.accepted === 0) {
        setError("Synthetic logs could not be stored. Nothing to assess.");
        return;
      }
      setStatus(
        `Injected ${summary.accepted.toLocaleString()} synthetic events` +
          (sources.length > 0 ? ` (source ${sources.join(", ")})` : "") +
          `. Running threat assessment…`,
      );
      const assessment = await onAssessLab(summary.eventIds);
      if (!assessment) {
        setStatus("Threat assessment could not be completed — see the Threat Assessment panel above.");
        return;
      }
      setStatus(
        `SYNTHETIC DEMO COMPLETE — ${summary.accepted.toLocaleString()} events, ` +
          `${assessment.alerts_count} alerts, ${assessment.incidents_count} incidents.`,
      );
      refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String((err as { message?: string })?.message ?? err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="animate-fade-up border-violet-800/40 bg-gradient-to-br from-slate-800/80 via-slate-800/70 to-violet-950/30">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <FlaskConical className="h-4 w-4 text-violet-400" /> Synthetic Threat Lab
          </CardTitle>
          <Badge variant="info" className="text-xs">Demo data</Badge>
        </div>
        <p className="text-xs text-slate-400">
          Generate realistic synthetic security telemetry for testing and demonstrations. Every event is marked{" "}
          <span className="font-mono text-violet-300">synthetic=true</span> and flows through the real
          ingestion → detection → correlation pipeline. Nothing is faked. Uses documentation IP ranges only.
        </p>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-2" role="radiogroup" aria-label="Threat scenario">
          {SCENARIO_ORDER.map((name) => (
            <button
              key={name}
              type="button"
              role="radio"
              aria-checked={scenario === name}
              onClick={() => setScenario(name)}
              className={`rounded-md border px-3 py-2 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-violet-500 ${
                scenario === name
                  ? "border-violet-500/60 bg-slate-900/60 text-slate-200 ring-1 ring-violet-500"
                  : "border-slate-700 bg-slate-900/60 text-slate-400 hover:border-slate-500 hover:text-slate-200"
              }`}
            >
              <span className={`block text-xs font-bold tracking-widest ${scenario === name ? SCENARIO_BADGE[name] : ""}`}>{SCENARIO_META[name].label}</span>
              <span className="block text-xs text-slate-400 opacity-80">{SCENARIO_META[name].tagline}</span>
            </button>
          ))}
          <button
            type="button"
            role="radio"
            aria-checked={scenario === "random"}
            onClick={() => setScenario("random")}
            className={`rounded-md border px-3 py-2 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-violet-500 ${
              scenario === "random"
                ? "border-violet-500/60 bg-slate-900/60 text-slate-200 ring-1 ring-violet-500"
                : "border-slate-700 bg-slate-900/60 text-slate-400 hover:border-slate-500 hover:text-slate-200"
            }`}
          >
            <span className={`flex items-center gap-1 text-xs font-bold tracking-widest ${scenario === "random" ? "hz-neon-violet" : ""}`}>
              <Dices className="h-3 w-3" /> RANDOM
            </span>
            <span className="block text-xs text-slate-400 opacity-80">Pick a scenario for me</span>
          </button>
        </div>
        {scenario !== "random" && (
          <p className="mt-2 text-xs text-slate-400" aria-live="polite">
            {SCENARIO_META[scenario].expects}
          </p>
        )}
        <Button size="sm" className="mt-3" disabled={busy || assessing} onClick={runLab} aria-label="Generate synthetic scenario and assess">
          {busy || assessing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <FlaskConical className="mr-2 h-4 w-4" />}
          Generate + assess
        </Button>
        {status && (
          <p className="mt-3 rounded-md border border-violet-800 bg-violet-950/40 p-3 text-sm text-violet-200" role="status">
            {status}
          </p>
        )}
        {error && (
          <p className="mt-3 rounded-md border border-red-800 bg-red-950/40 p-3 text-sm text-red-200" role="alert">
            {error}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
