export function getStatusColor(status: string): string {
  switch (status) {
    case "open":
    case "detected":
      return "hz-neon-info";
    case "investigating":
    case "acknowledged":
      return "hz-neon-warning";
    case "resolved":
      return "hz-neon-success";
    default:
      return "hz-neon-default";
  }
}
