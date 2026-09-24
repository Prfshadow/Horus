"""Timeline builder (M5)."""

from datetime import timezone
from typing import Any

from app.models.alert import Alert
from app.models.event import Event


def _ensure_utc(dt):
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def build_timeline(events: list[Event], alerts: list[Alert], limit: int = 600) -> tuple[list[dict], bool, int]:
    """Build unified timeline sorted by (timestamp, type_order, id).

    type_order: 0=event, 1=alert (events before alerts at same timestamp)
    Returns (entries, truncated, total_count)
    """
    entries: list[dict] = []
    for e in events:
        ts = _ensure_utc(e.timestamp)
        entries.append({"type": "event", "id": e.id, "timestamp": ts, "summary": e.message, "_sort": (ts, 0, e.id)})
    for a in alerts:
        ts = _ensure_utc(a.detected_at)
        entries.append({"type": "alert", "id": a.id, "timestamp": ts, "summary": a.summary, "_sort": (ts, 1, a.id)})
    entries.sort(key=lambda x: x["_sort"])
    total = len(entries)
    truncated = False
    if len(entries) > limit:
        entries = entries[:limit]
        truncated = True
    # Remove sort key
    for e in entries:
        e.pop("_sort", None)
    return entries, truncated, total
