"""Correlation API (M4): POST /correlate"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.db.session import get_db
from app.schemas.incident import CorrelateRequest, CorrelateResponse, IncidentRead
from app.services.incident_correlation import IncidentCorrelationService

router = APIRouter(prefix="/correlate", tags=["correlation"])
logger = get_logger(__name__)


@router.post("", response_model=CorrelateResponse)
def correlate(payload: CorrelateRequest, db: Session = Depends(get_db)) -> CorrelateResponse:
    evaluation_time = payload.evaluation_time
    if evaluation_time is None:
        evaluation_time = datetime.now(timezone.utc)
    if evaluation_time.tzinfo is None:
        evaluation_time = evaluation_time.replace(tzinfo=timezone.utc)

    service = IncidentCorrelationService()
    result = service.run_correlation(
        db=db,
        window_seconds=payload.window_seconds,
        evaluation_time=evaluation_time,
        strategy=payload.strategy,
        rule_names=payload.rule_names,
    )

    # Convert incidents to read models with alert_ids
    reads = []
    for inc in result["incidents"]:
        # Need to load alert_ids
        from sqlalchemy import select
        from app.models.incident_alert import IncidentAlert

        alert_ids = [r[0] for r in db.execute(select(IncidentAlert.alert_id).where(IncidentAlert.incident_id == inc.id)).all()]
        data = IncidentRead.model_validate(inc)
        data.alert_ids = sorted(alert_ids)
        reads.append(data)

    logger.info(
        "Correlate strategy=%s window=%s created=%s updated=%s correlated=%s",
        result["strategy"],
        result["window_seconds"],
        result["incidents_created"],
        result["incidents_updated"],
        result["alerts_correlated"],
    )

    return CorrelateResponse(
        window_seconds=result["window_seconds"],
        evaluation_time=result["evaluation_time"],
        strategy=result["strategy"],
        incidents_created=result["incidents_created"],
        incidents_updated=result["incidents_updated"],
        alerts_correlated=result["alerts_correlated"],
        incidents=reads,
    )
