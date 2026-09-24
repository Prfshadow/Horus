import { AlertTriangle, Server, Database, Clock } from "lucide-react";

export function AiProvenance({ provenance, evidenceMeta }: { provenance: { provider: string; model: string; prompt_version: string; schema_version: string; incident_id: number; evidence_ids_used: string[]; truncated: boolean; created_at: string } | null; evidenceMeta?: { alerts_used: number; events_used: number; truncated: boolean; total_alerts: number; total_events: number } }) {
  if (!provenance) return null;

  return (
    <div className="rounded-lg border border-slate-700 bg-slate-800/50 p-4">
      <h4 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
        <Database className="h-4 w-4 text-slate-400" /> Provenance
      </h4>
      <dl className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4 text-sm">
        <div className="flex flex-col gap-1">
          <dt className="text-slate-400">Provider</dt>
          <dd className="font-mono text-slate-200">{provenance.provider}</dd>
        </div>
        <div className="flex flex-col gap-1">
          <dt className="text-slate-400">Model</dt>
          <dd className="font-mono text-slate-200 truncate max-w-xs" title={provenance.model}>{provenance.model}</dd>
        </div>
        <div className="flex flex-col gap-1">
          <dt className="text-slate-400">Prompt Version</dt>
          <dd className="font-mono text-slate-200">{provenance.prompt_version}</dd>
        </div>
        <div className="flex flex-col gap-1">
          <dt className="text-slate-400">Schema Version</dt>
          <dd className="font-mono text-slate-200">{provenance.schema_version}</dd>
        </div>
        <div className="flex flex-col gap-1">
          <dt className="text-slate-400">Incident ID</dt>
          <dd className="font-mono text-slate-200">{provenance.incident_id}</dd>
        </div>
        <div className="flex flex-col gap-1">
          <dt className="text-slate-400">Created</dt>
          <dd className="font-mono text-slate-200" title={provenance.created_at}>{new Date(provenance.created_at).toISOString()}</dd>
        </div>
        <div className="flex flex-col gap-1">
          <dt className="text-slate-400">Evidence Used</dt>
          <dd className="font-mono text-slate-200">{provenance.evidence_ids_used.length}</dd>
        </div>
        <div className="flex flex-col gap-1">
          <dt className="text-slate-400">Truncated</dt>
          <dd className="flex items-center gap-1">
            {provenance.truncated ? (
              <>
                <AlertTriangle className="h-3 w-3 text-amber-400" />
                <span className="text-amber-300">Yes</span>
              </>
            ) : (
              <span className="text-emerald-300">No</span>
            )}
          </dd>
        </div>
      </dl>
      {evidenceMeta && (
        <div className="mt-3 pt-3 border-t border-slate-700">
          <p className="text-xs text-slate-400">
            Alerts used: <strong>{evidenceMeta.alerts_used}</strong> of <strong>{evidenceMeta.total_alerts}</strong>
            {evidenceMeta.truncated && <span className="ml-2 text-amber-300">(truncated)</span>}
          </p>
          <p className="text-xs text-slate-400 mt-1">
            Events used: <strong>{evidenceMeta.events_used}</strong> of <strong>{evidenceMeta.total_events}</strong>
            {evidenceMeta.truncated && <span className="ml-2 text-amber-300">(truncated)</span>}
          </p>
        </div>
      )}
    </div>
  );
}