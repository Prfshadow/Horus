/**
 * Pure dataset analysis for the landing injection gateway.
 *
 * Inspects raw log text to report event counts, format and size BEFORE
 * anything is sent to the backend. Never executes or interprets log
 * content — only counts lines and sniffs structural markers.
 */

export type LandingDatasetFormat = "JSON" | "JSONL" | "LOG" | "TXT";

export interface LandingDataset {
  name: string;
  lines: string[];
  format: LandingDatasetFormat;
  events: number;
  bytes: number;
  preview: string;
  size: number;
  truncated: boolean;
}

const TS_START = /(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}|\w{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2}|\[\d{2}\/\w{3}\/\d{4})/;

const TEXT_EXTENSIONS = ["json", "jsonl", "ndjson", "log", "txt", "csv", "out"];

export const LANDING_MAX_READ_BYTES = 32 * 1024 * 1024;

export function isTextualFile(name: string, mimeType: string): boolean {
  const ext = (name.match(/\.([a-z0-9]+)$/i) ?? [])[1]?.toLowerCase() ?? "";
  return TEXT_EXTENSIONS.includes(ext) || mimeType.startsWith("text/") || mimeType === "application/json";
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

export function detectLandingFormat(name: string, text: string): LandingDatasetFormat {
  const ext = (name.match(/\.([a-z0-9]+)$/i) ?? [])[1]?.toLowerCase() ?? "";
  const head = text.slice(0, 4096).trimStart();

  if (ext === "jsonl" || ext === "ndjson") return "JSONL";
  if (ext === "json") return "JSON";
  if (ext === "log" || ext === "out" || ext === "csv") return "LOG";

  if (head.startsWith("{") || head.startsWith("[")) {
    if (safeJsonParse(text.trim()) !== undefined) return "JSON";
    const sample = head.split("\n").filter((l) => l.trim()).slice(0, 5);
    if (sample.length > 0 && sample.every((l) => safeJsonParse(l.trim()) !== undefined)) return "JSONL";
  }
  if (TS_START.test(head)) return "LOG";
  return "TXT";
}

export function countLandingEvents(text: string, format: LandingDatasetFormat): number {
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  if (format === "JSON") {
    const parsed: unknown = safeJsonParse(text.trim());
    return Array.isArray(parsed) ? parsed.length : 1;
  }
  if (format === "LOG") {
    const stamped = lines.filter((l) => TS_START.test(l)).length;
    return stamped || lines.length;
  }
  return lines.length; // JSONL, TXT — one event per non-empty line
}

export function splitLandingLines(text: string, format: LandingDatasetFormat): string[] {
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  if (format === "JSON") {
    const parsed: unknown = safeJsonParse(text.trim());
    if (Array.isArray(parsed)) return parsed.map((item) => JSON.stringify(item));
    return [text.trim()];
  }
  return lines;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1073741824).toFixed(2)} GB`;
}

/** Build dataset metadata from raw text. Pure — no DOM, no network. */
export function buildLandingDataset(name: string, text: string, size?: number): LandingDataset {
  const format = detectLandingFormat(name, text);
  const firstLine = text.split(/\r?\n/).find((l) => l.trim()) ?? "";
  const bytes = size ?? new Blob([text]).size;
  return {
    name,
    lines: splitLandingLines(text, format),
    format,
    events: countLandingEvents(text, format),
    bytes,
    preview: firstLine.slice(0, 96),
    size: bytes,
    truncated: size !== undefined && size > LANDING_MAX_READ_BYTES,
  };
}
