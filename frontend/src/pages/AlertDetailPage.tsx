import * as React from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Copy, Check, Search, AlertTriangle } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Skeleton } from "@/components/ui/Skeleton";
import { useAlert } from "@/hooks/useAlerts";
import { formatDateTime } from "@/utils/formatDate";
import { getSeverityColor } from "@/utils/severity";
import { getStatusColor } from "@/utils/status";

function JsonBlock({ data }: { data: unknown }) {
  if (data == null || (typeof data === "object" && Object.keys(data as Record<string, unknown>).length === 0)) {
    return <p className="text-sm text-slate-500">No structured data.</p>;
  }
  let pretty: string;
  try {
    pretty = JSON.stringify(data, null, 2);
  } catch {
    pretty = String(data);
  }
  return (
    <pre className="max-h-64 overflow-auto rounded-md border border-slate-700 bg-slate-900 p-3 text-xs text-slate-200">
      <code>{pretty}</code>
    </pre>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = React.useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // ignore
    }
  };
  return (
    <Button variant="ghost" size="sm" onClick={onCopy} aria-label="Copy">
      {copied ? <Check className="h-4 w-4 text-emerald-500" /> : <Copy className="h-4 w-4" />}
      <span className="ml-1 text-xs">{copied ? "Copied" : "Copy"}</span>
    </Button>
  );
}

function EvidenceChip({ type, id }: { type: "alert" | "event"; id: number }) {
  const Icon = type === "alert" ? AlertTriangle : Search;
  const tone = type === "alert" ? "hz-neon-warning" : "hz-neon-info";
  const route = type === "alert" ? `/alerts/${id}` : `/events/${id}`;
  const label = type === "alert" ? `Alert #${id}` : `Event #${id}`;

  return (
    <Link
      to={route}
      className={`inline-flex items-center gap-1 rounded border px-2 py-1 text-xs font-mono ${tone} hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500`}
      aria-label={`View ${label}`}
    >
      <Icon className="h-3 w-3" />
      {type === "alert" ? "alert:" : "event:"}{id}
    </Link>
  );
}

export function AlertDetailPage() {
  const { id } = useParams<{ id: string }>();
  const alertId = Number(id);
  const isValidId = Number.isInteger(alertId) && alertId > 0;
  const { data: alert, isLoading, isError, error, refetch } = useAlert(isValidId ? alertId : 0);

  if (!isValidId) {
    return (
      <div className="space-y-4">
        <Link to="/alerts" className="inline-flex items-center text-sm text-sky-400 hover:text-sky-300">
          <ArrowLeft className="mr-1 h-4 w-4" /> Back to Alerts
        </Link>
        <Card>
          <CardContent className="p-8 text-center">
            <p className="text-sm font-medium text-slate-200">Invalid alert ID.</p>
            <p className="mt-1 text-xs text-slate-500">Expected a positive integer.</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-6 w-32" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (isError) {
    const isNotFound = (error as unknown as { status?: number })?.status === 404;
    return (
      <div className="space-y-4">
        <Link to="/alerts" className="inline-flex items-center text-sm text-sky-400 hover:text-sky-300">
          <ArrowLeft className="mr-1 h-4 w-4" /> Back to Alerts
        </Link>
        <Card>
          <CardContent className="p-8 text-center">
            <p className="text-sm font-medium text-slate-200">{isNotFound ? "Alert not found." : "Unable to load alert."}</p>
            <p className="mt-1 text-xs text-slate-500">{isNotFound ? `No alert with ID ${alertId}.` : String((error as unknown as { message?: string })?.message ?? error)}</p>
            <Button variant="outline" size="sm" className="mt-4" onClick={() => refetch()}>
              Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!alert) {
    return (
      <div className="space-y-4">
        <Link to="/alerts" className="inline-flex items-center text-sm text-sky-400 hover:text-sky-300">
          <ArrowLeft className="mr-1 h-4 w-4" /> Back to Alerts
        </Link>
        <Card>
          <CardContent className="p-8 text-center">
            <p className="text-sm text-slate-500">No alert data.</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Link to="/alerts" className="inline-flex items-center text-sm text-sky-400 hover:text-sky-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 rounded">
        <ArrowLeft className="mr-1 h-4 w-4" /> Back to Alerts
      </Link>

      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">{alert.rule_name}</h1>
          <p className="text-sm text-slate-400">Deterministic detection alert — evidence-backed.</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge className={getSeverityColor(alert.severity)}>{alert.severity}</Badge>
          <Badge className={getStatusColor(alert.status)}>{alert.status}</Badge>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Alert Details</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="space-y-3 text-sm">
              <div className="flex justify-between gap-4">
                <dt className="text-slate-400">Alert ID</dt>
                <dd className="font-mono text-slate-200">{alert.id}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-400">Rule ID</dt>
                <dd className="font-mono text-slate-200">{alert.rule_id}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-400">Rule Name</dt>
                <dd className="font-medium text-slate-200">{alert.rule_name}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-400">Status</dt>
                <dd><Badge className={getStatusColor(alert.status)}>{alert.status}</Badge></dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-400">Severity</dt>
                <dd><Badge className={getSeverityColor(alert.severity)}>{alert.severity}</Badge></dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-400">Detected At</dt>
                <dd className="text-slate-200" title={alert.detected_at}>{formatDateTime(alert.detected_at)}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-400">Created</dt>
                <dd className="text-slate-200" title={alert.created_at}>{formatDateTime(alert.created_at)}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-400">Updated</dt>
                <dd className="text-slate-200" title={alert.updated_at}>{formatDateTime(alert.updated_at)}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-400">First Event ID</dt>
                <dd className="font-mono text-slate-200">{alert.first_event_id}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-400">Last Event ID</dt>
                <dd className="font-mono text-slate-200">{alert.last_event_id}</dd>
              </div>
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="whitespace-pre-wrap break-words text-sm text-slate-200">{alert.summary}</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Context</CardTitle>
            <CopyButton text={JSON.stringify(alert.context, null, 2)} />
          </div>
          <p className="text-xs text-slate-500">Detection context — rule-dependent fields.</p>
        </CardHeader>
        <CardContent>
          <pre className="max-h-64 overflow-auto rounded-md border border-slate-700 bg-slate-900 p-3 text-xs text-slate-200">
            <code>{JSON.stringify(alert.context, null, 2)}</code>
          </pre>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Evidence Events</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {alert.evidence_event_ids.length === 0 ? (
            <p className="text-sm text-slate-500">No evidence events linked to this alert.</p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {alert.evidence_event_ids.map((eid, i) => (
                <Link key={i} to={`/events/${eid}`} className="inline-flex items-center gap-1 rounded border px-2 py-1 text-xs font-mono hz-neon-info hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500">
                  <Search className="h-3 w-3" />
                  event:{eid}
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}