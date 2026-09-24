"""Threat Assessment API: POST /api/v1/threat-assessment"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.db.session import get_db
from app.schemas.threat_assessment import ThreatAssessmentRequest, ThreatAssessmentResponse
from app.services.threat_assessment import assess_threats

router = APIRouter(prefix="/threat-assessment", tags=["threat-assessment"])
logger = get_logger(__name__)


@router.post("", response_model=ThreatAssessmentResponse)
def run_threat_assessment(payload: ThreatAssessmentRequest, db: Session = Depends(get_db)) -> ThreatAssessmentResponse:
    """Run full threat assessment pipeline on recent events.

    This endpoint:
    1. Runs detection on events in the specified window
    2. Correlates resulting alerts into incidents
    3. Computes threat level from deterministic evidence
    4. Returns a human-readable threat assessment

    When ``event_ids`` are supplied, the assessment is scoped to exactly
    those ingested events: evaluation_time defaults to the newest referenced
    event and only incidents linked to this run's alerts are reported.

    Args:
        payload: Request parameters including window, evaluation_time, etc.

    Returns:
        Threat assessment with level, explanation, and details.
    """
    evaluation_time = payload.evaluation_time
    if evaluation_time is not None and evaluation_time.tzinfo is None:
        evaluation_time = evaluation_time.replace(tzinfo=timezone.utc)

    assessment = assess_threats(
        db=db,
        window_seconds=payload.window_seconds,
        correlation_window_seconds=payload.correlation_window_seconds,
        evaluation_time=evaluation_time,
        correlation_strategy=payload.correlation_strategy,
        rule_names=payload.rule_names,
        synthetic=payload.synthetic,
        event_ids=payload.event_ids,
    )

    logger.info(
        "Threat assessment: level=%s alerts=%d incidents=%d events=%d synthetic=%s scoped=%s",
        assessment.threat_level,
        assessment.alerts_count,
        assessment.incidents_count,
        assessment.events_analyzed,
        assessment.synthetic,
        payload.event_ids is not None,
    )

    return ThreatAssessmentResponse(
        threat_level=assessment.threat_level,
        threat_title=assessment.threat_title,
        explanation=assessment.explanation,
        details=assessment.details,
        alerts_count=assessment.alerts_count,
        incidents_count=assessment.incidents_count,
        events_analyzed=assessment.events_analyzed,
        alert_severities=assessment.alert_severities,
        incident_severities=assessment.incident_severities,
        affected_entities=assessment.affected_entities,
        synthetic=assessment.synthetic,
        alert_ids=assessment.alert_ids,
        incident_ids=assessment.incident_ids,
    )