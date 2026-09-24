import { useMutation } from "@tanstack/react-query";
import { eventsApi } from "@/api/events";
import type { IngestResponse } from "@/types/api";
import { INGEST_BATCH_SIZE, INGEST_MAX_LINES, chunkLines } from "@/utils/ingest";

export type BatchIngestSummary = {
  accepted: number;
  failed: number;
  batches: number;
  truncated: boolean;
  eventIds: number[];
};

export function useIngestLogs() {
  return useMutation<IngestResponse, Error, { logs: string[]; source?: string }>({
    mutationFn: ({ logs, source }) => eventsApi.ingestLogs(logs, source),
    retry: 0,
  });
}

/** Send lines in sequential batches; aggregates accepted/failed. */
export async function ingestAllLines(
  lines: string[],
  source: string | undefined,
  sendBatch: (logs: string[], source?: string) => Promise<IngestResponse>,
  onProgress?: (current: number, total: number) => void,
): Promise<BatchIngestSummary> {
  const truncated = lines.length > INGEST_MAX_LINES;
  const usable = lines.slice(0, INGEST_MAX_LINES);
  const batches = chunkLines(usable, INGEST_BATCH_SIZE);
  let accepted = 0;
  let failed = 0;
  const eventIds: number[] = [];
  for (const [i, batch] of batches.entries()) {
    onProgress?.(i + 1, batches.length);
    const res = await sendBatch(batch, source);
    accepted += res.accepted;
    failed += res.failed;
    for (const r of res.results ?? []) {
      if (typeof r.event_id === "number") eventIds.push(r.event_id);
    }
  }
  return { accepted, failed, batches: batches.length, truncated, eventIds };
}
