"""InvestigationService (M5)."""

from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.logging_config import get_logger
from app.models.incident import Incident
from app.models.incident_alert import IncidentAlert
from app.models.alert import Alert
from app.models.alert_event import AlertEvent
from app.models.event import Event
from app.models.detection_rule import DetectionRule
from app.investigation.timeline import build_timeline
from app.investigation.summary import build_summary, extract_entities

logger = get_logger(__name__)

ALERT_LIMIT = 100
EVENT_LIMIT = 500
TIMELINE_LIMIT = 600


class InvestigationService:
    """Builds dynamic investigation context."""

    def get_investigation(
        self,
        db: Session,
        incident_id: int,
        include_events: bool = True,
        include_timeline: bool = True,
    ) -> dict:
        incident = db.get(Incident, incident_id)
        if not incident:
            raise ValueError("Incident not found")

        # Load alerts deterministically: detected_at ASC, id ASC
        stmt = (
            select(Alert)
            .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
            .where(IncidentAlert.incident_id == incident_id)
            .order_by(Alert.detected_at.asc(), Alert.id.asc())
        )
        all_alerts = list(db.execute(stmt).scalars().all())
        total_alerts = len(all_alerts)
        truncated_alerts = False
        if len(all_alerts) > ALERT_LIMIT:
            all_alerts = all_alerts[:ALERT_LIMIT]
            truncated_alerts = True

        # Collect direct evidence events from selected alerts
        event_map: dict[int, Event] = {}
        for alert in all_alerts:
            links = db.execute(select(AlertEvent).where(AlertEvent.alert_id == alert.id)).scalars().all()
            for link in links:
                if link.event_id in event_map:
                    continue
                ev = db.get(Event, link.event_id)
                if ev is None:
                    logger.warning("Orphan AlertEvent alert_id=%s event_id=%s", link.alert_id, link.event_id)
                    continue
                # Handle malformed extra_data gracefully
                try:
                    if ev.extra_data is not None and not isinstance(ev.extra_data, dict):
                        ev.extra_data = {}
                except Exception:
                    pass
                event_map[link.event_id] = ev

        # Deduplicate and sort events
        full_events = list(event_map.values())
        def _utc(dt):
            import datetime
            if dt.tzinfo is None:
                return dt.replace(tzinfo=datetime.timezone.utc)
            return dt
        full_events.sort(key=lambda e: (_utc(e.timestamp), e.id))
        total_events = len(full_events)
        truncated_events = False
        # Events to return (bounded)
        events_returned = full_events
        if len(events_returned) > EVENT_LIMIT:
            events_returned = events_returned[:EVENT_LIMIT]
            truncated_events = True

        # Summary and entities should be based on full events (before truncation) for accurate counts,
        # but event_count in summary reflects returned count
        # Build timeline from returned collections (if include flags)
        timeline_entries = []
        timeline_truncated = False
        timeline_total = 0
        if include_timeline:
            entries, truncated, total = build_timeline(events_returned if include_events else [], all_alerts, limit=TIMELINE_LIMIT)
            timeline_entries = entries
            timeline_truncated = truncated
            timeline_total = total
        else:
            timeline_entries = []

        # Determine events payload per include flag
        if include_events:
            events = events_returned
        else:
            events = []

        # Summary: use full_events for accurate unique counts, but pass returned counts
        truncated_any = truncated_alerts or truncated_events or timeline_truncated
        summary = build_summary(all_alerts, full_events, total_alerts, total_events, truncated_any)
        # Adjust summary's event_count to reflect returned count if truncated or include_events false?
        # Keep summary event_count as len(events) when include_events else total?
        # For determinism, keep as len(events) if include_events else 0, but total_event_count already true
        # Entities based on full events for completeness
        entities = extract_entities(all_alerts, full_events)

        # Detection info per alert
        detection = []
        for alert in all_alerts:
            rule = db.execute(select(DetectionRule).where(DetectionRule.id == alert.rule_id)).scalars().first()
            detection.append({
                "alert_id": alert.id,
                "rule_id": alert.rule_id,
                "rule_name": alert.rule_name,
                "rule_type": rule.rule_type if rule else None,
                "severity": alert.severity,
                "summary": alert.summary,
                "context": alert.context,
            })

        # Correlation
        correlation = {
            "strategy": incident.context.get("strategy") if incident.context else None,
            "correlation_key": incident.correlation_key,
            "correlation_window_seconds": incident.context.get("correlation_window_seconds") if incident.context else None,
        }

        return {
            "incident": incident,
            "alerts": all_alerts,
            "events": events,
            "timeline": timeline_entries,
            "correlation": correlation,
            "summary": summary,
            "entities": entities,
            "detection": detection,
            "truncated_alerts": truncated_alerts,
            "truncated_events": truncated_events,
            "timeline_truncated": timeline_truncated,
            "timeline_total": timeline_total,
        }
