import * as React from "react";
import { useThreatAssessment } from "@/hooks/useThreatAssessment";
import { useResetPipeline } from "@/hooks/useAdmin";
import { useQueryClient } from "@tanstack/react-query";
import { Loader2, ShieldAlert, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { ThreatAssessmentPanel } from "@/components/threat/ThreatAssessmentPanel";
import { ThreatLabPanel } from "@/components/lab/ThreatLabPanel";
import type { ThreatAssessmentResponse } from "@/api/threatAssessment";

function usePipelineRefresh() {
  const queryClient = useQueryClient();
  return () => {
    queryClient.invalidateQueries({ queryKey: ["stats"] });
    queryClient.invalidateQueries({ queryKey: ["events"] });
    queryClient.invalidateQueries({ queryKey: ["alerts"] });
    queryClient.invalidateQueries({ queryKey: ["incidents"] });
    queryClient.invalidateQueries({ queryKey: ["health"] });
  };
}

function ResetCard() {
  const refresh = usePipelineRefresh();
  const reset = useResetPipeline();
  const [confirm, setConfirm] = React.useState("");
  const [done, setDone] = React.useState<string | null>(null);

  const onReset = async () => {
    setDone(null);
    try {
      const res = await reset.mutateAsync();
      setDone(
        `Cleared ${res.events_deleted} events, ${res.alerts_deleted} alerts, ${res.incidents_deleted} incidents. Detection rules kept.`,
      );
      setConfirm("");
      refresh();
    } catch {
      // error rendered below from reset.error
    }
  };

  const armed = confirm.trim() === "RESET";

  return (
    <div className="hzc-panel hzc-corners border-red-800/50 bg-gradient-to-br from-slate-800/80 via-slate-800/70 to-red-950/30">
      <div className="hzc-panel-head">
        <h3 className="hzc-panel-title flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-red-400" /> Danger Zone — Reset Demo Data
        </h3>
      </div>
      <div className="hzc-panel-body">
        <p className="hz-body-sm text-slate-400 mb-4">
          Deletes <strong>all</strong> events, alerts, incidents and their links. Detection rules are kept. This
          cannot be undone.
        </p>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <div className="flex-1">
            <label htmlFor="reset-confirm" className="mb-1 block hz-body-sm text-slate-400">
              Type <span className="hz-font-mono text-red-300">RESET</span> to arm the button
            </label>
            <input
              id="reset-confirm"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder="RESET"
              autoComplete="off"
              className="hz-input hz-font-mono"
              aria-label="Type RESET to confirm"
            />
          </div>
          <Button
            variant="outline"
            onClick={onReset}
            disabled={!armed || reset.isPending}
            className="hz-btn hz-btn-outline border-red-700 text-red-300 hover:bg-red-950 disabled:opacity-40"
          >
            {reset.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Trash2 className="mr-2 h-4 w-4" />}
            Delete all pipeline data
          </Button>
        </div>
        {reset.isError && (
          <p className="mt-3 hzc-error-box" role="alert">
            Reset failed: {String((reset.error as { message?: string })?.message ?? reset.error)}
          </p>
        )}
        {done && (
          <p className="mt-3 rounded-md border border-emerald-800 bg-emerald-950/40 p-3 hz-body-sm text-emerald-200" role="status">
            {done}
          </p>
        )}
      </div>
    </div>
  );
}

/**
 * THREAT LAB — the synthetic/demo environment.
 *
 * Scenario generation, real ingestion, real detection, real correlation
 * and real threat assessment. Everything generated here is clearly marked
 * synthetic/demo data.
 */
export function ThreatLabPage() {
  const assess = useThreatAssessment();
  const [assessment, setAssessment] = React.useState<ThreatAssessmentResponse | null>(null);
  const [assessError, setAssessError] = React.useState<string | null>(null);
  const [lastEventIds, setLastEventIds] = React.useState<number[]>([]);

  const runAssessment = async (eventIds: number[]): Promise<ThreatAssessmentResponse | null> => {
    setAssessError(null);
    setAssessment(null);
    setLastEventIds(eventIds);
    try {
      const result = await assess.mutateAsync({
        window_seconds: 3600,
        correlation_window_seconds: 3600,
        synthetic: true,
        ...(eventIds.length > 0 ? { event_ids: eventIds } : {}),
      });
      setAssessment(result);
      return result;
    } catch (err) {
      setAssessError(err instanceof Error ? err.message : String((err as { message?: string })?.message ?? err));
      return null;
    }
  };

  return (
    <div className="hzc-section-gap">
      {/* Page Header */}
      <div className="hzc-page-head">
        <div>
          <p className="hzc-kicker">Synthetic environment</p>
          <h1 className="hzc-title">THREAT LAB</h1>
          <p className="hzc-subtitle">Generate synthetic security telemetry and run it through the real HORUS pipeline. Clearly labeled demo data — never real telemetry.</p>
        </div>
      </div>

      <div className="hzc-section-gap">
        <ThreatAssessmentPanel
          assessment={assessment}
          assessing={assess.isPending}
          error={assessError}
          onAssess={() => runAssessment(lastEventIds)}
          assessLabel="Reassess last run"
          showSyntheticWarning
        />
      </div>
      <ThreatLabPanel onAssessLab={runAssessment} assessing={assess.isPending} />
      <div className="hzc-section-gap">
        <ResetCard />
      </div>
    </div>
  );
}