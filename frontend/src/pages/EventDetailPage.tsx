import * as React from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Copy, Check } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Skeleton } from "@/components/ui/Skeleton";
import { useEvent } from "@/hooks/useEvents";
import { formatDateTime } from "@/utils/formatDate";
import { getSeverityColor } from "@/utils/severity";

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

export function EventDetailPage() {
  const { id } = useParams<{ id: string }>();
  const eventId = Number(id);
  const isValidId = Number.isInteger(eventId) && eventId > 0;
  const { data: event, isLoading, isError, error, refetch } = useEvent(isValidId ? eventId : 0);

  if (!isValidId) {
    return (
      <div className="space-y-4">
        <Link to="/events" className="inline-flex items-center text-sm text-sky-400 hover:text-sky-300">
          <ArrowLeft className="mr-1 h-4 w-4" /> Back to Events
        </Link>
        <Card>
          <CardContent className="p-8 text-center">
            <p className="text-sm font-medium text-slate-200">Invalid event ID.</p>
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
        <Link to="/events" className="inline-flex items-center text-sm text-sky-400 hover:text-sky-300">
          <ArrowLeft className="mr-1 h-4 w-4" /> Back to Events
        </Link>
        <Card>
          <CardContent className="p-8 text-center">
            <p className="text-sm font-medium text-slate-200">{isNotFound ? "Event not found." : "Unable to load event."}</p>
            <p className="mt-1 text-xs text-slate-500">{isNotFound ? `No event with ID ${eventId}.` : String((error as unknown as { message?: string })?.message ?? error)}</p>
            <Button variant="outline" size="sm" className="mt-4" onClick={() => refetch()}>
              Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!event) {
    return (
      <div className="space-y-4">
        <Link to="/events" className="inline-flex items-center text-sm text-sky-400 hover:text-sky-300">
          <ArrowLeft className="mr-1 h-4 w-4" /> Back to Events
        </Link>
        <Card>
          <CardContent className="p-8 text-center">
            <p className="text-sm text-slate-500">No event data.</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Link to="/events" className="inline-flex items-center text-sm text-sky-400 hover:text-sky-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 rounded">
        <ArrowLeft className="mr-1 h-4 w-4" /> Back to Events
      </Link>

      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Event #{event.id}</h1>
          <p className="text-sm text-slate-400">Normalized event detail — deterministic, evidence-backed.</p>
        </div>
        <Badge className={getSeverityColor(event.level)}>{event.level}</Badge>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Normalized Fields</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="space-y-3 text-sm">
              <div className="flex justify-between gap-4">
                <dt className="text-slate-400">Event ID</dt>
                <dd className="font-mono text-slate-200">{event.id}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-400">Timestamp</dt>
                <dd className="text-slate-200" title={event.timestamp}>{formatDateTime(event.timestamp)}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-400">Ingested</dt>
                <dd className="text-slate-200" title={event.ingested_at}>{formatDateTime(event.ingested_at)}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-400">Source</dt>
                <dd className="font-mono text-slate-200">{event.source}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-400">Service</dt>
                <dd className="text-slate-200">{event.service ?? "—"}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-400">Host</dt>
                <dd className="text-slate-200">{event.host ?? "—"}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-400">Level</dt>
                <dd><Badge className={getSeverityColor(event.level)}>{event.level}</Badge></dd>
              </div>
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Message</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="whitespace-pre-wrap break-words text-sm text-slate-200">{event.message}</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Raw Log — verbatim, untrusted</CardTitle>
            <CopyButton text={event.raw_log} />
          </div>
          <p className="text-xs text-slate-500">Original log line as received — rendered as escaped text, never as HTML.</p>
        </CardHeader>
        <CardContent>
          <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-md border border-slate-700 bg-slate-900 p-3 text-xs text-slate-200">
            <code>{event.raw_log}</code>
          </pre>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Extra Data — structured fields</CardTitle>
          <p className="text-xs text-slate-500">Flexible JSON remainder — parser-dependent.</p>
        </CardHeader>
        <CardContent>
          <JsonBlock data={event.extra_data} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Investigation Context</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-slate-400">
            Event-to-alert/incident tracing is not yet exposed as a direct lookup. Use the Investigation page for correlated incidents, or search alerts by source/time.
          </p>
          <div className="mt-3 flex gap-2">
            <Link to={`/incidents`}>
              <Button variant="outline" size="sm">View Incidents</Button>
            </Link>
            <Link to={`/alerts`}>
              <Button variant="outline" size="sm">View Alerts</Button>
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
