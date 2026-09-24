import * as React from "react";
import { ingestAllLines, useIngestLogs } from "@/hooks/useIngest";
import { useThreatAssessment } from "@/hooks/useThreatAssessment";
import type { ThreatAssessmentResponse } from "@/api/threatAssessment";

export type LandingPipelineStage = "idle" | "ingesting" | "analyzing" | "assessed" | "error";

export interface LandingPipelineResult {
  assessment: ThreatAssessmentResponse;
  accepted: number;
  failed: number;
  eventIds: number[];
}

interface RunOptions {
  source?: string;
  synthetic?: boolean;
  windowSeconds?: number;
  onProgress?: (message: string) => void;
}

/**
 * Single landing pipeline: real ingestion → real scoped threat assessment.
 *
 * Assessment is always scoped with the event IDs returned by ingestion, so
 * uploads with historical timestamps are analyzed exactly — never via an
 * unscoped "last N minutes" window. No manual /detect interaction.
 */
export function useLandingPipeline() {
  const ingest = useIngestLogs();
  const assess = useThreatAssessment();
  const [stage, setStage] = React.useState<LandingPipelineStage>("idle");
  const [progress, setProgress] = React.useState<string | null>(null);
  const [result, setResult] = React.useState<LandingPipelineResult | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  // Events stored by the last ingestion — survives an assessment failure so
  // the UI can report "logs stored, assessment failed" truthfully.
  const [accepted, setAccepted] = React.useState(0);
  // Last successful ingestion scope — retrying assessment must NOT re-ingest
  // (that would duplicate events).
  const lastScope = React.useRef<{ eventIds: number[]; synthetic: boolean; windowSeconds: number } | null>(null);

  const busy = ingest.isPending || assess.isPending || stage === "ingesting" || stage === "analyzing";

  const reset = React.useCallback(() => {
    setStage("idle");
    setProgress(null);
    setResult(null);
    setError(null);
    setAccepted(0);
    lastScope.current = null;
    ingest.reset();
  }, [ingest]);

  const run = React.useCallback(
    async (lines: string[], opts: RunOptions = {}): Promise<LandingPipelineResult> => {
      const { source, synthetic = false, windowSeconds = 3600, onProgress } = opts;
      setError(null);
      setResult(null);

      // Phase 1: real ingestion.
      setStage("ingesting");
      const ingestingMsg = `INGESTING DATA…`;
      setProgress(ingestingMsg);
      onProgress?.(ingestingMsg);
      let summary;
      try {
        summary = await ingestAllLines(
          lines,
          source,
          (batch, src) => ingest.mutateAsync({ logs: batch, source: src }),
          (current, total) => {
            const msg = `INGESTING DATA… batch ${current} of ${total}`;
            setProgress(msg);
            onProgress?.(msg);
          },
        );
      } catch (err) {
        const detail = err instanceof Error ? err.message : String(err);
        setError(detail || "Logs could not be stored.");
        setProgress(null);
        setAccepted(0);
        setStage("error");
        throw err instanceof Error ? err : new Error(detail);
      }

      if (summary.accepted === 0) {
        const message = "Logs could not be stored.";
        setError(message);
        setProgress(null);
        setAccepted(0);
        setStage("error");
        throw new Error(message);
      }
      setAccepted(summary.accepted);
      lastScope.current = { eventIds: summary.eventIds, synthetic, windowSeconds };

      // Phase 2: real scoped threat assessment over exactly these events.
      const analyzingMsg = `ANALYZING ${summary.accepted.toLocaleString()} EVENT${summary.accepted === 1 ? "" : "S"}…`;
      setStage("analyzing");
      setProgress(analyzingMsg);
      onProgress?.(analyzingMsg);
      try {
        const assessment = await assess.mutateAsync({
          window_seconds: windowSeconds,
          correlation_window_seconds: windowSeconds,
          event_ids: summary.eventIds,
          synthetic,
        });
        const out: LandingPipelineResult = {
          assessment,
          accepted: summary.accepted,
          failed: summary.failed,
          eventIds: summary.eventIds,
        };
        setResult(out);
        setProgress(null);
        setStage("assessed");
        return out;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        setError(message);
        setProgress(null);
        setStage("error");
        throw err instanceof Error ? err : new Error(message);
      }
    },
    [ingest, assess],
  );

  /**
   * Re-run only the threat-assessment step against the last ingested scope.
   * Never re-ingests (avoids duplicating events). Used for retry after an
   * assessment failure.
   */
  const retryAssessment = React.useCallback(async (): Promise<LandingPipelineResult> => {
    const scope = lastScope.current;
    if (!scope || scope.eventIds.length === 0) {
      throw new Error("Nothing to reassess — ingest logs first.");
    }
    setError(null);
    setResult(null);
    const analyzingMsg = `ANALYZING ${scope.eventIds.length.toLocaleString()} EVENT${scope.eventIds.length === 1 ? "" : "S"}…`;
    setStage("analyzing");
    setProgress(analyzingMsg);
    try {
      const assessment = await assess.mutateAsync({
        window_seconds: scope.windowSeconds,
        correlation_window_seconds: scope.windowSeconds,
        event_ids: scope.eventIds,
        synthetic: scope.synthetic,
      });
      const out: LandingPipelineResult = {
        assessment,
        accepted: scope.eventIds.length,
        failed: 0,
        eventIds: scope.eventIds,
      };
      setResult(out);
      setProgress(null);
      setStage("assessed");
      return out;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
      setProgress(null);
      setStage("error");
      throw err instanceof Error ? err : new Error(message);
    }
  }, [assess]);

  return { stage, progress, result, error, accepted, busy, run, retryAssessment, reset };
}
