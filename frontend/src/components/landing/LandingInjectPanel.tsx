import * as React from "react";
import { Link } from "react-router-dom";
import { buildLandingDataset, isTextualFile, LANDING_MAX_READ_BYTES, formatBytes, type LandingDataset } from "@/utils/landingDataset";
import type { useLandingPipeline } from "@/components/landing/useLandingPipeline";
import { ThreatAssessmentPanel } from "@/components/threat/ThreatAssessmentPanel";
import { PasteModal } from "@/components/landing/PasteModal";

type Pipeline = ReturnType<typeof useLandingPipeline>;

function readText(blob: Blob): Promise<string> {
  const maybeText = (blob as unknown as { text?: unknown }).text;
  if (typeof maybeText === "function") {
    try {
      const out = (maybeText as () => unknown).call(blob);
      if (out instanceof Promise) {
        return (out as Promise<unknown>).then(
          (t) => (typeof t === "string" ? t : String(t ?? "")),
          () =>
            new Promise<string>((resolve, reject) => {
              const reader = new FileReader();
              reader.onload = () => resolve(String(reader.result ?? ""));
              reader.onerror = () => reject(reader.error ?? new Error("read failed"));
              reader.readAsText(blob);
            }),
        );
      }
    } catch {
      // fall through to FileReader
    }
  }
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.onerror = () => reject(reader.error ?? new Error("read failed"));
    reader.readAsText(blob);
  });
}

interface LandingInjectPanelProps {
  pipeline: Pipeline;
  pingKey: number;
}

/**
 * The injection gateway: dropzone → staged dataset → ingesting →
 * analyzing → real threat result. File, drag/drop, paste and synthetic
 * entries all flow through the same real pipeline (no fakes).
 */
export function LandingInjectPanel({ pipeline, pingKey }: LandingInjectPanelProps) {
  const [dataset, setDataset] = React.useState<LandingDataset | null>(null);
  const [dragActive, setDragActive] = React.useState(false);
  const [pasteOpen, setPasteOpen] = React.useState(false);
  const [localError, setLocalError] = React.useState<string | null>(null);
  const fileInputRef = React.useRef<HTMLInputElement>(null);
  const zoneRef = React.useRef<HTMLDivElement>(null);
  const dragDepth = React.useRef(0);
  const { stage, progress, result, error, accepted, busy, run, retryAssessment, reset } = pipeline;

  const staged = dataset !== null && (stage === "idle" || stage === "error");

  const stageDataset = React.useCallback(
    (name: string, text: string, size?: number) => {
      if (!text.trim()) {
        setLocalError("Nothing to inject — the file is empty.");
        return;
      }
      setLocalError(null);
      reset();
      setDataset(buildLandingDataset(name, text, size));
    },
    [reset],
  );

  const loadFile = React.useCallback(
    async (file: File) => {
      if (!isTextualFile(file.name, file.type)) {
        setLocalError("Unsupported file — HORUS ingests text-based logs: JSON, JSONL, LOG or TXT.");
        return;
      }
      try {
        const blob = file.size > LANDING_MAX_READ_BYTES ? file.slice(0, LANDING_MAX_READ_BYTES) : file;
        const text = await readText(blob);
        stageDataset(file.name, text, file.size);
      } catch {
        setLocalError("The file could not be read in this browser.");
      }
    },
    [stageDataset],
  );

  // Swallow stray drops so the browser never navigates away.
  React.useEffect(() => {
    const prevent = (e: DragEvent) => e.preventDefault();
    window.addEventListener("dragover", prevent);
    window.addEventListener("drop", prevent);
    return () => {
      window.removeEventListener("dragover", prevent);
      window.removeEventListener("drop", prevent);
    };
  }, []);

  React.useEffect(() => {
    const onDragEnter = (e: DragEvent) => {
      if (!(e.dataTransfer && [...(e.dataTransfer.types ?? [])].includes("Files"))) return;
      if (dragDepth.current++ === 0) document.body.classList.add("hz-is-dragging");
    };
    const onDragLeave = () => {
      if (dragDepth.current > 0 && --dragDepth.current === 0) {
        document.body.classList.remove("hz-is-dragging");
      }
    };
    const onDrop = () => {
      dragDepth.current = 0;
      document.body.classList.remove("hz-is-dragging");
    };
    document.addEventListener("dragenter", onDragEnter);
    document.addEventListener("dragleave", onDragLeave);
    document.addEventListener("drop", onDrop);
    return () => {
      document.removeEventListener("dragenter", onDragEnter);
      document.removeEventListener("dragleave", onDragLeave);
      document.removeEventListener("drop", onDrop);
      document.body.classList.remove("hz-is-dragging");
    };
  }, []);

  // Header "Inject Data" ping support.
  const [pinged, setPinged] = React.useState(false);
  const lastPing = React.useRef(pingKey);
  React.useEffect(() => {
    if (pingKey === lastPing.current) return;
    lastPing.current = pingKey;
    setPinged(true);
    zoneRef.current?.focus({ preventScroll: true });
    const id = window.setTimeout(() => setPinged(false), 1400);
    return () => window.clearTimeout(id);
  }, [pingKey]);

  const openPicker = () => fileInputRef.current?.click();

  const handleZoneKeyDown = (e: React.KeyboardEvent) => {
    if (e.target !== e.currentTarget) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      openPicker();
    }
  };

  const handleAnalyze = () => {
    if (!dataset || dataset.lines.length === 0) {
      setLocalError("Nothing to analyze — stage a dataset first.");
      return;
    }
    void run(dataset.lines, { source: "landing-upload", synthetic: false }).catch(() => {
      // Error state is exposed by the pipeline hook; nothing to do here.
    });
  };

  const handleReplace = () => {
    reset();
    setDataset(null);
    setLocalError(null);
    openPicker();
  };

  const handleClear = () => {
    reset();
    setDataset(null);
    setLocalError(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const showDropzone = !staged && stage !== "ingesting" && stage !== "analyzing" && stage !== "assessed";
  const showStaged = staged;
  const showProgress = stage === "ingesting" || stage === "analyzing";
  const showResult = stage === "assessed" && result !== null;
  const showError = stage === "error";

  return (
    <>
      <div
        ref={zoneRef}
        className={`hz-injection${dragActive ? " is-dragover" : ""}${pinged ? " is-pinged" : ""}`}
        role="button"
        tabIndex={0}
        aria-label="Inject data — drop log files here, or press Enter to choose a file"
        onKeyDown={handleZoneKeyDown}
        onClick={(e) => {
          const t = e.target as HTMLElement;
          if (t.closest("button, a, input, textarea, select")) return;
          if (showDropzone) openPicker();
        }}
        onDragOver={(e) => {
          e.preventDefault();
          e.dataTransfer.dropEffect = "copy";
          setDragActive(true);
        }}
        onDragLeave={(e) => {
          if (!e.currentTarget.contains(e.relatedTarget as Node)) setDragActive(false);
        }}
        onDrop={(e) => {
          e.preventDefault();
          setDragActive(false);
          dragDepth.current = 0;
          document.body.classList.remove("hz-is-dragging");
          const file = e.dataTransfer.files?.[0];
          if (file) {
            void loadFile(file);
            return;
          }
          const text = e.dataTransfer.getData("text/plain");
          if (text?.trim()) {
            stageDataset("dropped-text.txt", text);
          }
        }}
      >
        <span className="hz-corner tl" aria-hidden="true" />
        <span className="hz-corner tr" aria-hidden="true" />
        <span className="hz-corner bl" aria-hidden="true" />
        <span className="hz-corner br" aria-hidden="true" />
        <span className="hz-pulse-ring" aria-hidden="true" />

        {showDropzone && (
          <div className="hz-drop-stage">
            <svg className="hz-drop-icon" viewBox="0 0 48 48" aria-hidden="true">
              <path d="M24 5.5 42.5 24 24 42.5 5.5 24Z" />
              <path d="M24 30.5 V15.5 M17.6 21.8 24 15.4 30.4 21.8" />
            </svg>
            <h2 className="hz-drop-title">INJECT DATA</h2>
            <p className="hz-drop-hint">
              <span className="hz-hint-idle">Drop log files here or choose from disk</span>
              <span className="hz-hint-drop">Release to inject</span>
            </p>
            <div className="hz-drop-actions">
              <button type="button" className="hz-btn hz-btn-outline" onClick={openPicker}>
                <svg viewBox="0 0 16 16" aria-hidden="true">
                  <path d="M4 1.5h5l3 3v10H4Z" />
                  <path d="M9 1.5v3h3" />
                </svg>
                Choose File
              </button>
              <button type="button" className="hz-btn hz-btn-ghost" onClick={() => setPasteOpen(true)}>
                <svg viewBox="0 0 16 16" aria-hidden="true">
                  <rect x="3" y="3.5" width="10" height="11" rx="1.5" />
                  <path d="M6 3.5V2h4v1.5" />
                </svg>
                Paste Logs
              </button>
            </div>
            <p className="hz-formats">
              <span>JSON</span>
              <i aria-hidden="true" />
              <span>JSONL</span>
              <i aria-hidden="true" />
              <span>LOG</span>
              <i aria-hidden="true" />
              <span>TXT</span>
            </p>
            {localError && (
              <p className="hz-field-error" role="alert" style={{ marginTop: "1rem" }}>
                {localError}
              </p>
            )}
          </div>
        )}

        {showStaged && dataset && (
          <div className="hz-data-stage hz-enter" key={`${dataset.name}-${dataset.events}`}>
            <p className="hz-data-kicker">DATASET STAGED FOR ANALYSIS</p>
            <p className="hz-data-name">{dataset.name}</p>
            <p className="hz-data-preview">{dataset.preview || "—"}</p>
            <dl className="hz-data-stats">
              <div>
                <dt>Events</dt>
                <dd>
                  {dataset.truncated ? "≈" : ""}
                  {dataset.events.toLocaleString()}
                </dd>
              </div>
              <div>
                <dt>Format</dt>
                <dd>{dataset.format}</dd>
              </div>
              <div>
                <dt>Size</dt>
                <dd>{formatBytes(dataset.size)}</dd>
              </div>
            </dl>
            <div className="hz-data-actions">
              <button type="button" className="hz-btn hz-btn-primary" onClick={handleAnalyze} disabled={busy}>
                <svg viewBox="0 0 16 16" aria-hidden="true">
                  <rect x="3.5" y="7" width="9" height="6.5" rx="1" />
                  <path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" />
                </svg>
                Analyze Data
              </button>
              <button type="button" className="hz-btn hz-btn-ghost" onClick={handleReplace}>
                Replace
              </button>
              <button type="button" className="hz-btn hz-btn-ghost" onClick={handleClear}>
                Clear
              </button>
            </div>
            {localError && (
              <p className="hz-field-error" role="alert" style={{ marginTop: "1rem" }}>
                {localError}
              </p>
            )}
          </div>
        )}

        {showProgress && (
          <div className="hz-progress-stage" role="status" aria-live="polite">
            <div className="hz-spinner" aria-hidden="true">
              <div className="hz-spinner-ring" />
              <div className="hz-spinner-arc" />
            </div>
            <p className="hz-progress-title">{stage === "ingesting" ? "INGESTING DATA" : "ANALYZING"}</p>
            <p className="hz-progress-detail">{progress ?? (stage === "ingesting" ? "Sending events to the HORUS engine…" : "Running deterministic detection…")}</p>
            <div className="hz-progress-bar" aria-hidden="true">
              <div className="hz-progress-fill" />
            </div>
          </div>
        )}

        {showError && (
          <div className="hz-error-stage" role="alert">
            {accepted === 0 ? (
              <>
                <p className="hz-error-title">Logs could not be stored.</p>
                {error !== "Logs could not be stored." && (
                  <p className="hz-error-detail">{error}</p>
                )}
                <div className="hz-data-actions">
                  <button type="button" className="hz-btn hz-btn-outline" onClick={handleAnalyze} disabled={busy}>
                    Retry
                  </button>
                  <button type="button" className="hz-btn hz-btn-ghost" onClick={handleClear}>
                    Clear
                  </button>
                </div>
              </>
            ) : (
              <>
                <p className="hz-error-title">Logs stored successfully. Threat assessment could not be completed.</p>
                <p className="hz-error-detail">{error}</p>
                <div className="hz-data-actions">
                  <button
                    type="button"
                    className="hz-btn hz-btn-outline"
                    disabled={busy}
                    onClick={() => {
                      void retryAssessment().catch(() => {
                        // Error state is exposed by the pipeline hook.
                      });
                    }}
                  >
                    Retry Analysis
                  </button>
                  <button type="button" className="hz-btn hz-btn-ghost" onClick={handleClear}>
                    Clear
                  </button>
                </div>
              </>
            )}
          </div>
        )}

        {showResult && result && (
          <div className="hz-assessed-stage">
            <ThreatAssessmentPanel
              assessment={result.assessment}
              assessing={false}
              error={null}
              eventsReceived={result.accepted}
              onAssess={() => {
                void retryAssessment().catch(() => {
                  // Error state is exposed by the pipeline hook.
                });
              }}
              assessLabel="Reassess events"
              incidentId={(result.assessment.incident_ids ?? [])[0]}
            />
            <div className="hz-data-actions" style={{ justifyContent: "center" }}>
              <button type="button" className="hz-btn hz-btn-ghost" onClick={handleClear}>
                New Analysis
              </button>
            </div>
          </div>
        )}

        <input
          ref={fileInputRef}
          type="file"
          className="hz-sr-only"
          tabIndex={-1}
          aria-hidden="true"
          accept=".json,.jsonl,.ndjson,.log,.txt,.csv,text/plain,application/json"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void loadFile(file);
            e.target.value = "";
          }}
        />
      </div>

      <p className="hz-synthetic-link">
        <Link to="/threat-lab">
          Try synthetic data <span aria-hidden="true">→</span>
        </Link>
      </p>

      <PasteModal
        open={pasteOpen}
        onClose={() => setPasteOpen(false)}
        onInject={(text) => {
          setPasteOpen(false);
          stageDataset("pasted-events.txt", text);
        }}
      />
    </>
  );
}
