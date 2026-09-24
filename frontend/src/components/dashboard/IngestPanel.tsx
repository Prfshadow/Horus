import * as React from "react";
import { Link } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { ClipboardPaste, FileUp, Loader2, RotateCcw, Upload } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { ingestAllLines, useIngestLogs } from "@/hooks/useIngest";
import { INGEST_BATCH_SIZE, INGEST_MAX_LINES, chunkLines, parseLogLines } from "@/utils/ingest";

export { INGEST_BATCH_SIZE, INGEST_MAX_LINES, chunkLines, parseLogLines };

export function readFileText(file: File): Promise<string> {
  if (typeof file.text === "function") {
    try {
      const out = file.text() as unknown;
      if (out instanceof Promise) {
        return (out as Promise<unknown>).then(
          (t) => (typeof t === "string" ? t : String(t ?? "")),
          () => readViaReader(file),
        );
      }
    } catch {
      // fall through to FileReader
    }
  }
  return readViaReader(file);
}

function readViaReader(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.onerror = () => reject(reader.error ?? new Error("read failed"));
    reader.readAsText(file);
  });
}

export function IngestPanel({ onIngested }: { onIngested?: (summary: { accepted: number; failed: number; eventIds: number[] }) => void }) {
  const queryClient = useQueryClient();
  const ingest = useIngestLogs();
  const [text, setText] = React.useState("");
  const [source, setSource] = React.useState("auth-service");
  const [fileName, setFileName] = React.useState<string | null>(null);
  const [fileLines, setFileLines] = React.useState<string[]>([]);
  const [fileError, setFileError] = React.useState<string | null>(null);
  const [progress, setProgress] = React.useState<string | null>(null);
  const [result, setResult] = React.useState<{ accepted: number; failed: number; batches: number; truncated: boolean } | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const fileRef = React.useRef<HTMLInputElement>(null);

  const onFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    setFileError(null);
    if (!file) {
      setFileName(null);
      setFileLines([]);
      return;
    }
    try {
      const content = await readFileText(file);
      const lines = parseLogLines(content);
      if (lines.length === 0) {
        setFileError("File contains no non-empty lines.");
        setFileName(null);
        setFileLines([]);
        return;
      }
      setFileName(file.name);
      setFileLines(lines);
    } catch {
      setFileError("Could not read that file as text.");
      setFileName(null);
      setFileLines([]);
    }
  };

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setResult(null);
    const pasted = parseLogLines(text);
    const combined = [...fileLines, ...pasted];
    if (combined.length === 0) {
      setError("Paste some log lines or choose a log file first.");
      return;
    }
    try {
      const summary = await ingestAllLines(
        combined,
        source.trim() || undefined,
        (logs, src) => ingest.mutateAsync({ logs, source: src }),
        (current, total) => setProgress(`Uploading batch ${current} of ${total}…`),
      );
      setResult(summary);
      setProgress(null);
      queryClient.invalidateQueries({ queryKey: ["stats"] });
      queryClient.invalidateQueries({ queryKey: ["events"] });
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["health"] });
      // Only trigger assessment when at least one event was stored.
      if (summary.accepted > 0) {
        onIngested?.({ accepted: summary.accepted, failed: summary.failed, eventIds: summary.eventIds });
      }
    } catch (err) {
      setProgress(null);
      setError(err instanceof Error ? err.message : String((err as { message?: string })?.message ?? err));
    }
  };

  const onReset = () => {
    setText("");
    setSource("auth-service");
    setFileName(null);
    setFileLines([]);
    setFileError(null);
    setProgress(null);
    setResult(null);
    setError(null);
    ingest.reset();
    if (fileRef.current) fileRef.current.value = "";
  };

  const pending = ingest.isPending;
  const totalReady = fileLines.length + parseLogLines(text).length;

  return (
    <Card className="animate-fade-up border-sky-800/40 bg-gradient-to-br from-slate-800/80 via-slate-800/70 to-sky-950/40">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-4 w-4 text-sky-400" /> Inject Logs
          </CardTitle>
          <Badge variant="info" className="text-xs">No terminal needed</Badge>
        </div>
        <p className="text-xs text-slate-400">
          Paste log lines or upload a <span className="font-mono">.log / .txt / .json</span> file. Large files are
          sent in {INGEST_BATCH_SIZE}-line batches (up to {INGEST_MAX_LINES.toLocaleString()} lines per submit).
        </p>
      </CardHeader>
      <CardContent>
        <form onSubmit={onSubmit} className="space-y-3">
          <div className="grid gap-3 lg:grid-cols-[1fr_220px]">
            <div>
              <label htmlFor="ingest-text" className="mb-1 flex items-center gap-1 text-xs text-slate-400">
                <ClipboardPaste className="h-3 w-3" /> Paste log lines
              </label>
              <textarea
                id="ingest-text"
                value={text}
                onChange={(e) => setText(e.target.value)}
                rows={5}
                placeholder='{"timestamp":"2026-09-14T10:00:00Z","level":"ERROR","message":"Failed password","ip":"10.0.0.5"}'
                className="w-full rounded-md border border-slate-600 bg-slate-900/80 px-3 py-2 font-mono text-xs text-slate-100 placeholder:text-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                aria-label="Paste log lines"
              />
            </div>
            <div className="space-y-3">
              <div>
                <label htmlFor="ingest-source" className="mb-1 block text-xs text-slate-400">Source</label>
                <input
                  id="ingest-source"
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  placeholder="auth-service"
                  className="w-full rounded-md border border-slate-600 bg-slate-900/80 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-500 focus:outline-none"
                  aria-label="Default source"
                />
              </div>
              <div>
                <label htmlFor="ingest-file" className="mb-1 flex items-center gap-1 text-xs text-slate-400">
                  <FileUp className="h-3 w-3" /> Log file
                </label>
                <input
                  id="ingest-file"
                  ref={fileRef}
                  type="file"
                  accept=".log,.txt,.json,.csv"
                  onChange={onFileChange}
                  className="w-full text-xs text-slate-400 file:mr-2 file:rounded-md file:border file:border-slate-600 file:bg-slate-800 file:px-3 file:py-1.5 file:text-xs file:text-slate-200 hover:file:bg-slate-700"
                  aria-label="Upload log file"
                />
                {fileName && (
                  <p className="mt-1 truncate text-xs text-slate-400" title={fileName}>
                    {fileName} — <span className="font-mono">{fileLines.length.toLocaleString()} lines</span>
                  </p>
                )}
                {fileError && <p className="mt-1 text-xs text-red-300">{fileError}</p>}
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button type="submit" disabled={pending} aria-busy={pending}>
              {pending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Upload className="mr-2 h-4 w-4" />}
              {pending ? "Injecting…" : "Inject logs"}
            </Button>
            <Button type="button" variant="ghost" size="sm" onClick={onReset} disabled={pending}>
              <RotateCcw className="mr-1 h-3 w-3" /> Clear
            </Button>
            <span className="text-xs text-slate-500" aria-live="polite">
              {progress ?? `${totalReady.toLocaleString()} line${totalReady === 1 ? "" : "s"} ready`}
            </span>
            {result && (
              <Link to="/events" className="ml-auto text-xs text-sky-400 hover:text-sky-300">
                View in Events Explorer →
              </Link>
            )}
          </div>

          {result && (
            <div className="rounded-md border border-emerald-800 bg-emerald-950/40 p-3 text-sm" role="status">
              <p className="text-emerald-200">
                Stored <strong className="font-mono">{result.accepted.toLocaleString()}</strong>
                {result.failed > 0 && (
                  <>
                    {" "}• <span className="text-amber-300">{result.failed.toLocaleString()} failed to parse</span>
                  </>
                )}{" "}
                across {result.batches} batch{result.batches === 1 ? "" : "es"}.
              </p>
              {result.truncated && (
                <p className="mt-1 text-xs text-amber-300">
                  Capped at {INGEST_MAX_LINES.toLocaleString()} lines per submit — upload the remainder separately.
                </p>
              )}
              <p className="mt-1 text-xs text-slate-400">Threat assessment runs automatically in the panel below.</p>
            </div>
          )}
          {error && (
            <div className="rounded-md border border-red-800 bg-red-950/40 p-3 text-sm text-red-200" role="alert">
              {error}
            </div>
          )}
        </form>
      </CardContent>
    </Card>
  );
}
