"""Stats endpoint for dashboard (M7.2) — deterministic aggregates."""

from datetime import datetime, timezone
from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from app.db.session import get_db
from app.models.event import Event
from app.models.alert import Alert
from app.models.incident import Incident
from app.schemas.stats import StatsResponse, StatsEvents, StatsAlerts, StatsIncidents

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)) -> StatsResponse:
    # Events total — single COUNT query
    events_total = db.execute(select(func.count(Event.id))).scalar_one()

    # Alerts aggregates — efficient, no fetching rows
    alerts_total = db.execute(select(func.count(Alert.id))).scalar_one()
    active_alerts = db.execute(
        select(func.count(Alert.id)).where(Alert.status.in_(["detected", "acknowledged"]))
    ).scalar_one()

    # by_severity and by_status via GROUP BY
    alerts_by_severity_rows = db.execute(select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)).all()
    alerts_by_status_rows = db.execute(select(Alert.status, func.count(Alert.id)).group_by(Alert.status)).all()

    alerts_by_severity = {severity: count for severity, count in alerts_by_severity_rows}
    alerts_by_status = {status: count for status, count in alerts_by_status_rows}

    # Incidents aggregates
    incidents_total = db.execute(select(func.count(Incident.id))).scalar_one()
    open_incidents = db.execute(select(func.count(Incident.id)).where(Incident.status == "open")).scalar_one()
    investigating_incidents = db.execute(select(func.count(Incident.id)).where(Incident.status == "investigating")).scalar_one()
    resolved_incidents = db.execute(select(func.count(Incident.id)).where(Incident.status == "resolved")).scalar_one()

    incidents_by_severity_rows = db.execute(select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)).all()
    incidents_by_severity = {severity: count for severity, count in incidents_by_severity_rows}

    return StatsResponse(
        events=StatsEvents(total=events_total),
        alerts=StatsAlerts(
            total=alerts_total,
            active=active_alerts,
            by_severity=alerts_by_severity,
            by_status=alerts_by_status,
        ),
        incidents=StatsIncidents(
            total=incidents_total,
            open=open_incidents,
            investigating=investigating_incidents,
            resolved=resolved_incidents,
            by_severity=incidents_by_severity,
        ),
        generated_at=datetime.now(timezone.utc),
    )
