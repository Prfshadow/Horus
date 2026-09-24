"""Summary and entity extraction (M5)."""

from datetime import timezone
from collections import Counter
from typing import Any

from app.models.alert import Alert
from app.models.event import Event


def _ensure_utc(dt):
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def build_summary(alerts: list[Alert], events: list[Event], total_alerts: int, total_events: int, truncated: bool) -> dict:
    # Unique counts from returned events (bounded)
    sources = set(e.source for e in events if e.source)
    hosts = set(e.host for e in events if e.host)
    # also from extra_data host
    for e in events:
        if not e.host and e.extra_data and "host" in e.extra_data:
            v = e.extra_data.get("host")
            if v:
                hosts.add(str(v))
    services = set(e.service for e in events if e.service)

    # Severity breakdown from returned alerts
    breakdown: dict[str, int] = dict(Counter(a.severity for a in alerts))

    # Time span from events+alerts if any
    timestamps = []
    for e in events:
        timestamps.append(_ensure_utc(e.timestamp))
    for a in alerts:
        timestamps.append(_ensure_utc(a.detected_at))
    if timestamps:
        span = int((max(timestamps) - min(timestamps)).total_seconds())
    else:
        span = 0

    return {
        "alert_count": len(alerts),
        "event_count": len(events),
        "unique_sources": len(sources),
        "unique_hosts": len(hosts),
        "unique_services": len(services),
        "severity_breakdown": breakdown,
        "time_span_seconds": span,
        "total_alert_count": total_alerts,
        "total_event_count": total_events,
        "truncated": truncated,
    }


def extract_entities(alerts: list[Alert], events: list[Event]) -> dict:
    ips: set[str] = set()
    hosts: set[str] = set()
    services: set[str] = set()
    sources: set[str] = set()

    for e in events:
        if e.source:
            sources.add(e.source)
        if e.service:
            services.add(e.service)
        if e.host:
            hosts.add(e.host)
        if e.extra_data:
            # Handle malformed gracefully
            try:
                if "ip" in e.extra_data and e.extra_data["ip"]:
                    ips.add(str(e.extra_data["ip"]))
                if not e.host and "host" in e.extra_data and e.extra_data["host"]:
                    hosts.add(str(e.extra_data["host"]))
            except Exception:
                pass
    for a in alerts:
        try:
            ctx = a.context or {}
            # strategy source_ip -> group_key is ip
            if "group_key" in ctx and ctx["group_key"]:
                # Only add if strategy is source_ip (check incident context not available here; add anyway if looks like IP)
                val = str(ctx["group_key"])
                if "." in val or ":" in val:
                    ips.add(val)
        except Exception:
            pass
        # Also check extra_data? already via events
    return {
        "ips": sorted(ips),
        "hosts": sorted(hosts),
        "services": sorted(services),
        "sources": sorted(sources),
    }
