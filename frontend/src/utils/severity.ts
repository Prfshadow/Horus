export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | string;

export function getSeverityColor(severity: string): string {
  switch (severity?.toUpperCase()) {
    case "CRITICAL":
      return "hz-neon-critical";
    case "HIGH":
      return "hz-neon-high";
    case "MEDIUM":
      return "hz-neon-medium";
    case "LOW":
      return "hz-neon-low";
    default:
      return "hz-neon-default";
  }
}

export function getSeverityDot(severity: string): string {
  switch (severity?.toUpperCase()) {
    case "CRITICAL":
      return "bg-red-500";
    case "HIGH":
      return "bg-orange-500";
    case "MEDIUM":
      return "bg-amber-500";
    case "LOW":
      return "bg-slate-500";
    default:
      return "bg-slate-500";
  }
}
