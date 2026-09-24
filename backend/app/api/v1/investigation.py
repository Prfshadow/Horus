"""Investigation API (M5)."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.db.session import get_db
from app.investigation.service import InvestigationService
from app.schemas.investigation import InvestigationContextResponse, InvestigationIncident, InvestigationAlert, InvestigationEvent, TimelineEntry, InvestigationCorrelation, InvestigationSummary, InvestigationEntities, InvestigationDetection

router = APIRouter(prefix="/incidents", tags=["investigation"])
logger = get_logger(__name__)


@router.get("/{incident_id}/investigation", response_model=InvestigationContextResponse)
def get_investigation(
    incident_id: int,
    include_events: bool = Query(default=True),
    include_timeline: bool = Query(default=True),
    db: Session = Depends(get_db),
) -> InvestigationContextResponse:
    service = InvestigationService()
    try:
        result = service.get_investigation(db, incident_id, include_events=include_events, include_timeline=include_timeline)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception:
        logger.exception("Investigation failed for incident %s", incident_id)
        raise HTTPException(status_code=500, detail="Investigation failed")

    # Build response
    inc = result["incident"]
    incident_read = InvestigationIncident.model_validate(inc)

    # Alerts: already sorted, transform
    alerts_read = []
    for a in result["alerts"]:
        # Need evidence_event_ids
        from sqlalchemy import select
        from app.models.alert_event import AlertEvent

        ids = [r[0] for r in db.execute(select(AlertEvent.event_id).where(AlertEvent.alert_id == a.id)).all()]
        # lookup rule_type
        from app.models.detection_rule import DetectionRule
        rule = db.execute(select(DetectionRule).where(DetectionRule.id == a.rule_id)).scalars().first()
        data = InvestigationAlert(
            id=a.id,
            rule_id=a.rule_id,
            rule_name=a.rule_name,
            rule_type=rule.rule_type if rule else None,
            severity=a.severity,
            status=a.status,
            detected_at=a.detected_at,
            summary=a.summary,
            context=a.context,
            first_event_id=a.first_event_id,
            last_event_id=a.last_event_id,
            evidence_event_ids=sorted(ids),
        )
        alerts_read.append(data)

    events_read = []
    for e in result["events"]:
        events_read.append(InvestigationEvent.model_validate(e))

    timeline_read = [TimelineEntry(**t) for t in result["timeline"]]

    correlation = InvestigationCorrelation(**result["correlation"])
    summary = InvestigationSummary(**result["summary"])
    entities = InvestigationEntities(**result["entities"])
    detection = [InvestigationDetection(**d) for d in result["detection"]]

    return InvestigationContextResponse(
        incident=incident_read,
        alerts=alerts_read,
        events=events_read,
        timeline=timeline_read,
        correlation=correlation,
        summary=summary,
        entities=entities,
        detection=detection,
    )
