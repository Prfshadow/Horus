export const INGEST_BATCH_SIZE = 500;
export const INGEST_MAX_LINES = 5000;

export function parseLogLines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

export function chunkLines<T>(lines: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < lines.length; i += size) {
    chunks.push(lines.slice(i, i + size));
  }
  return chunks;
}
