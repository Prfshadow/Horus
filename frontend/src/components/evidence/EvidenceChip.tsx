import { Link } from "react-router-dom";
import { AlertTriangle, Search, Layers } from "lucide-react";

export function EvidenceChip({ id }: { id: string }) {
  const match = id.match(/^(incident|alert|event):(\d+)$/);
  if (!match) {
    return (
      <span className="inline-flex items-center gap-1 rounded border px-2 py-1 text-xs font-mono text-slate-400 border-slate-700 bg-slate-800">
        {id}
      </span>
    );
  }

  const [, type, numStr] = match;
  const num = Number(numStr);
  const Icon = type === "alert" ? AlertTriangle : type === "event" ? Search : Layers;
  const tone = type === "alert" ? "hz-neon-warning" : type === "event" ? "hz-neon-info" : "hz-neon-violet";
  const route = type === "alert" ? `/alerts/${num}` : type === "event" ? `/events/${num}` : `/incidents/${num}`;
  const label = type === "alert" ? `Alert #${num}` : type === "event" ? `Event #${num}` : `Incident #${num}`;

  return (
    <Link
      to={route}
      className={`inline-flex items-center gap-1 rounded border px-2 py-1 text-xs font-mono ${tone} hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500`}
      aria-label={`View ${label}`}
    >
      <Icon className="h-3 w-3" />
      {id}
    </Link>
  );
}

export function EvidenceChipList({ ids }: { ids: string[] }) {
  if (!ids || ids.length === 0) return null;
  return (
    <span className="flex items-center gap-1 flex-wrap">
      {ids.map((id, idx) => (
        <EvidenceChip key={`${id}-${idx}`} id={id} />
      ))}
    </span>
  );
}