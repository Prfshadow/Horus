"""IncidentCorrelationService (M4)."""

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import select

from app.correlation.engine import IncidentCorrelationEngine
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.incident_alert import IncidentAlert

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _max_severity(severities: list[str]) -> str:
    max_s = "LOW"
    max_val = -1
    for s in severities:
        v = SEVERITY_ORDER.get(s.upper(), -1)
        if v > max_val:
            max_val = v
            max_s = s.upper()
    return max_s


class IncidentCorrelationService:
    """DB-aware, transactional correlation."""

    def __init__(self, engine: Optional[IncidentCorrelationEngine] = None):
        self.engine = engine or IncidentCorrelationEngine()

    def run_correlation(
        self,
        db: Session,
        window_seconds: int = 3600,
        evaluation_time: Optional[datetime] = None,
        strategy: str = "source_ip",
        rule_names: Optional[list[str]] = None,
    ) -> dict:
        if evaluation_time is None:
            evaluation_time = datetime.now(timezone.utc)
        if evaluation_time.tzinfo is None:
            evaluation_time = evaluation_time.replace(tzinfo=timezone.utc)

        # Bounded candidate alerts
        cutoff = evaluation_time - timedelta(seconds=window_seconds)
        stmt = select(Alert).where(Alert.status.in_(["detected", "acknowledged"])).where(Alert.detected_at >= cutoff).where(Alert.detected_at <= evaluation_time)
        if rule_names:
            stmt = stmt.where(Alert.rule_name.in_(rule_names))
        # Exclude already assigned
        stmt = stmt.where(~Alert.id.in_(select(IncidentAlert.alert_id)))
        stmt = stmt.order_by(Alert.detected_at.asc(), Alert.id.asc())
        candidates = list(db.execute(stmt).scalars().all())

        if not candidates:
            return {
                "window_seconds": window_seconds,
                "evaluation_time": evaluation_time,
                "strategy": strategy,
                "incidents_created": 0,
                "incidents_updated": 0,
                "alerts_correlated": 0,
                "incidents": [],
            }

        groups = self.engine.correlate(candidates, strategy, db)

        incidents_created = 0
        alerts_correlated = 0
        touched_incidents: dict[int, Incident] = {}
        created_ids: set[int] = set()
        updated_ids: set[int] = set()

        try:
            for correlation_key, alerts in groups.items():
                alerts = sorted(alerts, key=lambda a: (a.detected_at, a.id))
                for alert in alerts:
                    alert_detected = alert.detected_at
                    if alert_detected.tzinfo is None:
                        alert_detected = alert_detected.replace(tzinfo=timezone.utc)
                    # Find existing incident for this key (most recent first)
                    existing = (
                        db.execute(
                            select(Incident)
                            .where(Incident.correlation_key == correlation_key)
                            .where(Incident.status != "resolved")
                            .order_by(Incident.last_seen_at.desc())
                        )
                        .scalars()
                        .all()
                    )
                    target: Optional[Incident] = None
                    for inc in existing:
                        inc_last = inc.last_seen_at
                        if inc_last.tzinfo is None:
                            inc_last = inc_last.replace(tzinfo=timezone.utc)
                        if inc_last <= alert_detected <= inc_last + timedelta(seconds=window_seconds):
                            target = inc
                            break
                    if target:
                        # Guard duplicate
                        if db.execute(select(IncidentAlert).where(IncidentAlert.alert_id == alert.id)).scalars().first():
                            continue
                        db.add(IncidentAlert(incident_id=target.id, alert_id=alert.id))
                        db.flush()
                        # Update last_seen_at if later
                        cur_last = target.last_seen_at
                        if cur_last.tzinfo is None:
                            cur_last = cur_last.replace(tzinfo=timezone.utc)
                        if alert_detected > cur_last:
                            target.last_seen_at = alert_detected
                        # Update severity to max of all linked alerts
                        linked_ids = [r[0] for r in db.execute(select(IncidentAlert.alert_id).where(IncidentAlert.incident_id == target.id)).all()]
                        severities = []
                        for aid in linked_ids:
                            a = db.get(Alert, aid)
                            if a:
                                severities.append(a.severity)
                        severities.append(target.severity)
                        target.severity = _max_severity(severities)
                        target.updated_at = datetime.now(timezone.utc)
                        # Update title
                        target.title = f"{len(linked_ids)} alerts for {correlation_key}"
                        touched_incidents[target.id] = target
                        updated_ids.add(target.id)
                        alerts_correlated += 1
                    else:
                        new_inc = Incident(
                            title=f"1 alerts for {correlation_key}",
                            status="open",
                            severity=alert.severity,
                            correlation_key=correlation_key,
                            context={
                                "strategy": strategy,
                                "correlation_window_seconds": window_seconds,
                                "correlation_key": correlation_key,
                            },
                            first_seen_at=alert_detected,
                            last_seen_at=alert_detected,
                        )
                        db.add(new_inc)
                        db.flush()
                        db.add(IncidentAlert(incident_id=new_inc.id, alert_id=alert.id))
                        db.flush()
                        touched_incidents[new_inc.id] = new_inc
                        created_ids.add(new_inc.id)
                        incidents_created += 1
                        alerts_correlated += 1

            incidents_updated = len(updated_ids - created_ids)
            db.commit()
            result_incidents = sorted(touched_incidents.values(), key=lambda x: x.last_seen_at, reverse=True)
            return {
                "window_seconds": window_seconds,
                "evaluation_time": evaluation_time,
                "strategy": strategy,
                "incidents_created": incidents_created,
                "incidents_updated": incidents_updated,
                "alerts_correlated": alerts_correlated,
                "incidents": result_incidents,
            }
        except Exception:
            db.rollback()
            raise
