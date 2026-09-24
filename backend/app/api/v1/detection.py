"""Manual detection trigger API (M3)."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.db.session import get_db
from app.detection.engine import DetectionEngine
from app.schemas.detection import AlertRead, DetectRequest, DetectResponse
from app.services.detection import DetectionService

router = APIRouter(prefix="/detect", tags=["detection"])
logger = get_logger(__name__)


def _to_read(alert, db: Session) -> AlertRead:
    ids = [link.event_id for link in alert.evidence_links]
    data = AlertRead.model_validate(alert)
    data.evidence_event_ids = sorted(ids)
    return data


@router.post("", response_model=DetectResponse)
def run_detection(payload: DetectRequest, db: Session = Depends(get_db)) -> DetectResponse:
    evaluation_time = payload.evaluation_time
    if evaluation_time is None:
        evaluation_time = datetime.now(timezone.utc)
    if evaluation_time.tzinfo is None:
        evaluation_time = evaluation_time.replace(tzinfo=timezone.utc)

    engine = DetectionEngine()
    service = DetectionService(engine=engine)
    alerts = service.run_detection(
        db=db,
        window_seconds=payload.window_seconds,
        evaluation_time=evaluation_time,
        rule_names=payload.rule_names,
    )

    # Convert to read models
    reads = [_to_read(a, db) for a in alerts]

    logger.info("Detection run: window=%s, alerts_created=%s", payload.window_seconds, len(reads))

    return DetectResponse(
        window_seconds=payload.window_seconds,
        evaluation_time=evaluation_time,
        alerts_created=len(reads),
        alerts=reads,
    )
