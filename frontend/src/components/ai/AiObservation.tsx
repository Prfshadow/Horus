import { EvidenceChipList } from "@/components/evidence/EvidenceChip";
import { Shield, Brain, HelpCircle } from "lucide-react";

export function AiObservation({ observation }: { observation: { statement: string; type: "fact" | "inference" | "uncertainty"; evidence_ids: string[]; confidence?: "low" | "medium" | "high" | null } }) {
  const isFact = observation.type === "fact";
  const isInference = observation.type === "inference";
  const isUncertainty = observation.type === "uncertainty";

  const badgeConfig = isFact
    ? { label: "FACT", icon: Shield, color: "hz-neon-success", iconColor: "text-emerald-400" }
    : isInference
    ? { label: "INFERENCE", icon: Brain, color: "hz-neon-warning", iconColor: "text-amber-400" }
    : { label: "UNCERTAINTY", icon: HelpCircle, color: "hz-neon-default", iconColor: "text-slate-400" };

  const ConfidencePill = () => {
    if (!isInference || !observation.confidence) return null;
    const confColor = observation.confidence === "high" ? "hz-neon-success" : observation.confidence === "medium" ? "hz-neon-warning" : "hz-neon-error";
    return <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium border ${confColor}`}>Confidence: {observation.confidence}</span>;
  };

  const IconComponent = badgeConfig.icon;

  return (
    <div className="rounded-lg border p-4 bg-slate-800/50">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between mb-2">
        <div className="flex items-center gap-2">
          <IconComponent className={`h-4 w-4 ${badgeConfig.iconColor}`} aria-hidden="true" />
          <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium border ${badgeConfig.color}`}>{badgeConfig.label}</span>
          <ConfidencePill />
        </div>
      </div>
      <p className="text-sm text-slate-300 whitespace-pre-wrap break-words">{observation.statement}</p>
      {observation.evidence_ids && observation.evidence_ids.length > 0 && (
        <div className="mt-2">
          <span className="text-xs text-slate-400 mr-2">Evidence:</span>
          <EvidenceChipList ids={observation.evidence_ids} />
        </div>
      )}
    </div>
  );
}