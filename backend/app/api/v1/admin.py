"""Admin API — dev data reset (delete pipeline data, keep config).

DELETEs all Events, Alerts, AlertEvents, Incidents and IncidentAlerts.
Detection rules are preserved (they are configuration, seeded on startup).
Requires explicit {"confirm": "RESET"} body to prevent accidents.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.db.session import get_db
from app.models.alert import Alert
from app.models.alert_event import AlertEvent
from app.models.event import Event
from app.models.incident import Incident
from app.models.incident_alert import IncidentAlert
from app.schemas.admin import ResetRequest, ResetResponse

router = APIRouter(prefix="/admin", tags=["admin"])
logger = get_logger(__name__)


@router.post("/reset", response_model=ResetResponse)
def reset_pipeline(payload: ResetRequest, db: Session = Depends(get_db)) -> ResetResponse:
    """Delete all pipeline data (events/alerts/incidents + links)."""
    if payload.confirm != "RESET":
        raise HTTPException(status_code=400, detail='confirm must be "RESET"')

    try:
        counts = {
            "events": db.execute(select(func.count()).select_from(Event)).scalar_one(),
            "alerts": db.execute(select(func.count()).select_from(Alert)).scalar_one(),
            "incidents": db.execute(select(func.count()).select_from(Incident)).scalar_one(),
            "alert_events": db.execute(select(func.count()).select_from(AlertEvent)).scalar_one(),
            "incident_alerts": db.execute(select(func.count()).select_from(IncidentAlert)).scalar_one(),
        }
        # FK-safe order: join rows first, then parents.
        db.execute(delete(IncidentAlert))
        db.execute(delete(AlertEvent))
        db.execute(delete(Incident))
        db.execute(delete(Alert))
        db.execute(delete(Event))
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Pipeline reset failed")
        raise HTTPException(status_code=500, detail="Reset failed")

    logger.info(
        "Pipeline reset: events=%s alerts=%s incidents=%s",
        counts["events"],
        counts["alerts"],
        counts["incidents"],
    )
    return ResetResponse(
        events_deleted=counts["events"],
        alerts_deleted=counts["alerts"],
        incidents_deleted=counts["incidents"],
        alert_events_deleted=counts["alert_events"],
        incident_alerts_deleted=counts["incident_alerts"],
    )
