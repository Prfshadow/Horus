"""EvidenceSelector — deterministic, bounded, no DB."""

from typing import Any

ALERTS_LIMIT = 10
EVENTS_LIMIT = 20
TIMELINE_LIMIT = 30
RAW_LOG_LIMIT = 500
TOTAL_CHARS_LIMIT = 25000


def _truncate_raw(raw: str) -> str:
    if len(raw) <= RAW_LOG_LIMIT:
        return raw
    return raw[:RAW_LOG_LIMIT] + "[…truncated]"


def _select_earliest_latest(items: list[Any], limit: int) -> tuple[list[Any], bool]:
    """Deterministic selection: if >limit, earliest half + latest half."""
    if len(items) <= limit:
        return items, False
    half = limit // 2
    # items are already sorted deterministically by caller
    return items[:half] + items[- (limit - half):], True


class EvidenceSelector:
    """Selects RelevantEvidence from M5 InvestigationContext dict."""

    def select(self, ctx: dict) -> dict:
        """
        ctx is dict from InvestigationService.get_investigation with keys:
        incident, alerts, events, timeline, correlation, summary, entities, detection, ...
        Returns RelevantEvidence dict with truncation metadata and allowed_ids.
        """
        incident = ctx["incident"]
        alerts_all = ctx.get("alerts", [])
        events_all = ctx.get("events", [])
        timeline_all = ctx.get("timeline", [])
        # Note: ctx events/alerts are already sorted and deduped by M5, but we re-apply M6 limits deterministically

        # Alerts: already sorted detected_at ASC, id ASC by M5; apply M6 limit 10 with earliest 5 + latest 5
        total_alerts = len(alerts_all)
        alerts, alerts_truncated = _select_earliest_latest(alerts_all, ALERTS_LIMIT)

        # Events: sorted timestamp ASC, id ASC by M5; apply 20
        total_events = len(events_all)
        events, events_truncated = _select_earliest_latest(events_all, EVENTS_LIMIT)

        # Timeline: sorted (timestamp, type_order, id) by M5; apply 30
        total_timeline = len(timeline_all)
        timeline, timeline_truncated = _select_earliest_latest(timeline_all, TIMELINE_LIMIT)

        # Raw log truncation per event (copy to avoid mutating original)
        events_for_evidence = []
        for e in events:
            # e is Event model instance or dict; handle both
            raw = getattr(e, "raw_log", None)
            if raw is None and isinstance(e, dict):
                raw = e.get("raw_log", "")
            truncated_raw = _truncate_raw(raw) if isinstance(raw, str) else raw
            # Create shallow copy dict for evidence
            if hasattr(e, "model_validate"):
                # shouldn't happen
                ev_dict = e
            else:
                # Build evidence dict
                try:
                    ev_dict = {
                        "id": e.id,
                        "timestamp": getattr(e, "timestamp", None),
                        "source": getattr(e, "source", None),
                        "level": getattr(e, "level", None),
                        "service": getattr(e, "service", None),
                        "host": getattr(e, "host", None),
                        "message": getattr(e, "message", None),
                        "raw_log": truncated_raw,
                        "extra_data": getattr(e, "extra_data", None),
                    }
                except Exception:
                    # Handle dict case
                    ev_dict = dict(e) if isinstance(e, dict) else {"raw_log": truncated_raw}
                    if isinstance(e, dict) and "raw_log" in e:
                        ev_dict["raw_log"] = truncated_raw
            events_for_evidence.append(ev_dict)

        # Alerts for evidence: keep minimal fields, with truncated IDs
        alerts_for_evidence = []
        for a in alerts:
            try:
                alerts_for_evidence.append({
                    "id": a.id,
                    "rule_name": getattr(a, "rule_name", None),
                    "severity": getattr(a, "severity", None),
                    "status": getattr(a, "status", None),
                    "detected_at": getattr(a, "detected_at", None),
                    "summary": getattr(a, "summary", None),
                    "context": getattr(a, "context", None),
                    "evidence_event_ids": getattr(a, "evidence_event_ids", [] ) if hasattr(a, "evidence_event_ids") else (getattr(a, "context", {}) or {}).get("evidence_event_ids", []),
                })
            except Exception:
                alerts_for_evidence.append({"id": getattr(a, "id", 0)})

        # Evidence IDs
        allowed_ids = set()
        allowed_ids.add(f"incident:{incident.id if hasattr(incident, 'id') else incident.get('id')}")
        for a in alerts:
            allowed_ids.add(f"alert:{a.id if hasattr(a, 'id') else a.get('id')}")
        for e in events:
            eid = e.id if hasattr(e, "id") else e.get("id") if isinstance(e, dict) else None
            if eid is not None:
                allowed_ids.add(f"event:{eid}")

        evidence_truncated = alerts_truncated or events_truncated or timeline_truncated

        # Total chars budget
        # Estimate: serialize evidence blocks roughly
        import json

        def _approx_chars(obj):
            try:
                return len(json.dumps(obj, default=str))
            except Exception:
                return 0

        total_chars = 0
        total_chars += _approx_chars(alerts_for_evidence)
        total_chars += _approx_chars(events_for_evidence)
        total_chars += _approx_chars(timeline)
        # If exceeds 25000, truncate lower priority first: timeline, then events raw logs already truncated, then events
        # For M6.1, if still over, we keep as is but mark truncated; actual prompt builder will enforce total limit by further truncating events
        total_chars_truncated = total_chars > TOTAL_CHARS_LIMIT

        evidence_truncated = evidence_truncated or total_chars_truncated

        return {
            "incident": incident,
            "alerts": alerts_for_evidence,
            "events": events_for_evidence,
            "timeline": timeline,
            "correlation": ctx.get("correlation"),
            "summary": ctx.get("summary"),
            "entities": ctx.get("entities"),
            "detection": ctx.get("detection"),
            "allowed_ids": sorted(allowed_ids),
            "truncation": {
                "alerts_truncated": alerts_truncated,
                "events_truncated": events_truncated,
                "timeline_truncated": timeline_truncated,
                "evidence_truncated": evidence_truncated,
                "total_alerts": total_alerts,
                "total_events": total_events,
                "total_timeline_entries": total_timeline,
                "total_chars_approx": total_chars,
                "total_chars_truncated": total_chars_truncated,
            },
            "limits": {
                "alerts": ALERTS_LIMIT,
                "events": EVENTS_LIMIT,
                "timeline": TIMELINE_LIMIT,
                "raw_log": RAW_LOG_LIMIT,
                "total_chars": TOTAL_CHARS_LIMIT,
            }
        }
