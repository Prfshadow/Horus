import { format, formatDistanceToNow } from "date-fns";

export function formatDateTime(iso: string): string {
  try {
    const d = new Date(iso);
    return format(d, "MMM d, yyyy HH:mm:ss");
  } catch {
    return iso;
  }
}

export function formatRelative(iso: string): string {
  try {
    const d = new Date(iso);
    return formatDistanceToNow(d, { addSuffix: true });
  } catch {
    return iso;
  }
}

export function formatLastUpdated(date: Date): string {
  return format(date, "HH:mm:ss");
}
