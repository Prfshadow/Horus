import * as React from "react";
import { Link, useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, Search, RefreshCw, Layers } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Skeleton } from "@/components/ui/Skeleton";
import { useIncident } from "@/hooks/useIncidents";
import { formatDateTime } from "@/utils/formatDate";
import { getSeverityColor } from "@/utils/severity";
import { getStatusColor } from "@/utils/status";

export function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const incidentId = Number(id);
  const isValidId = Number.isInteger(incidentId) && incidentId > 0;
  const navigate = useNavigate();

  const { data: incident, isLoading, isError, error, refetch } = useIncident(isValidId ? incidentId : 0);

  if (!isValidId) {
    return (
      <div className="space-y-4">
        <Link to="/incidents" className="inline-flex items-center text-sm text-sky-400 hover:text-sky-300">
          <ArrowLeft className="mr-1 h-4 w-4" /> Back to Incidents
        </Link>
        <Card>
          <CardContent className="p-8 text-center">
            <p className="text-sm font-medium text-slate-200">Invalid incident ID.</p>
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
        <Link to="/incidents" className="inline-flex items-center text-sm text-sky-400 hover:text-sky-300">
          <ArrowLeft className="mr-1 h-4 w-4" /> Back to Incidents
        </Link>
        <Card>
          <CardContent className="p-8 text-center">
            <p className="text-sm font-medium text-slate-200">{isNotFound ? "Incident not found." : "Unable to load incident."}</p>
            <p className="mt-1 text-xs text-slate-500">{isNotFound ? `No incident with ID ${incidentId}.` : String((error as unknown as { message?: string })?.message ?? error)}</p>
            <Button variant="outline" size="sm" className="mt-4" onClick={() => refetch()}>
              Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="space-y-4">
        <Link to="/incidents" className="inline-flex items-center text-sm text-sky-400 hover:text-sky-300">
          <ArrowLeft className="mr-1 h-4 w-4" /> Back to Incidents
        </Link>
        <Card>
          <CardContent className="p-8 text-center">
            <p className="text-sm text-slate-500">No incident data.</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Link to="/incidents" className="inline-flex items-center text-sm text-sky-400 hover:text-sky-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 rounded">
        <ArrowLeft className="mr-1 h-4 w-4" /> Back to Incidents
      </Link>

      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">{incident.title}</h1>
          <p className="text-sm text-slate-400">Correlated incident — deterministic, evidence-backed.</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge className={getSeverityColor(incident.severity)}>{incident.severity}</Badge>
          <Badge className={getStatusColor(incident.status)}>{incident.status}</Badge>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Layers className="h-4 w-4" /> Incident Details
          </CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 text-sm">
            <div className="flex flex-col gap-1">
              <dt className="text-slate-400">Incident ID</dt>
              <dd className="font-mono text-slate-200">{incident.id}</dd>
            </div>
            <div className="flex flex-col gap-1">
              <dt className="text-slate-400">Correlation Key</dt>
              <dd className="font-mono text-slate-200">{incident.correlation_key}</dd>
            </div>
            <div className="flex flex-col gap-1">
              <dt className="text-slate-400">First Seen</dt>
              <dd className="text-slate-200" title={incident.first_seen_at}>{formatDateTime(incident.first_seen_at)}</dd>
            </div>
            <div className="flex flex-col gap-1">
              <dt className="text-slate-400">Last Seen</dt>
              <dd className="text-slate-200" title={incident.last_seen_at}>{formatDateTime(incident.last_seen_at)}</dd>
            </div>
            <div className="flex flex-col gap-1 sm:col-span-2">
              <dt className="text-slate-400">Created</dt>
              <dd className="text-slate-200" title={incident.created_at}>{formatDateTime(incident.created_at)}</dd>
            </div>
            <div className="flex flex-col gap-1 sm:col-span-2">
              <dt className="text-slate-400">Updated</dt>
              <dd className="text-slate-200" title={incident.updated_at}>{formatDateTime(incident.updated_at)}</dd>
            </div>
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Search className="h-4 w-4" /> Linked Alerts
          </CardTitle>
        </CardHeader>
        <CardContent>
          {incident.alert_ids.length === 0 ? (
            <p className="text-sm text-slate-500">No alerts linked to this incident.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {incident.alert_ids.map((alertId) => (
                <Link key={alertId} to={`/alerts/${alertId}`} className="inline-flex items-center gap-1 rounded-md border border-slate-600 bg-slate-900 px-3 py-1.5 text-sm font-mono text-sky-400 hover:bg-slate-800 hover:text-sky-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500">
                  <Layers className="h-3 w-3" />
                  Alert #{alertId}
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <div className="pt-2 flex gap-2">
        <Link to={`/incidents/${incidentId}/investigation`}>
          <Button>
            <Search className="mr-2 h-4 w-4" /> Investigate
          </Button>
        </Link>
      </div>
    </div>
  );
}