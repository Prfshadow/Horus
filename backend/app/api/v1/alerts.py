"""Alerts API (M3+M7.4).

M3: Basic alert listing and status updates.
M7.4: Server-side pagination, filtering, sorting, and search for alerts.
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.db.session import get_db
from app.models.alert import Alert
from app.schemas.detection import (
    AlertRead,
    AlertUpdate,
    AlertQueryParams,
    PaginatedAlertResponse,
)

router = APIRouter(prefix="/alerts", tags=["alerts"])
logger = get_logger(__name__)

# Whitelisted sortable columns for deterministic ordering
SORTABLE_FIELDS = {
    "detected_at": "detected_at",
    "severity": "severity",
    "status": "status",
    "rule_name": "rule_name",
    "id": "id",
}

# Searchable fields for text search
SEARCHABLE_FIELDS = ["summary", "rule_name"]


def _to_read(alert, db: Session) -> "AlertRead":
    """Convert Alert model to AlertRead with evidence IDs."""
    from app.models.alert_event import AlertEvent
    from sqlalchemy import select as sa_select

    ids = [
        row.event_id
        for row in db.execute(
            sa_select(AlertEvent.event_id).where(AlertEvent.alert_id == alert.id)
        ).all()
    ]
    data = AlertRead.model_validate(alert)
    data.evidence_event_ids = sorted(ids)
    return data


@router.get("", response_model=PaginatedAlertResponse)
def list_alerts(
    params: "AlertQueryParams" = Depends(),
    db: Session = Depends(get_db),
) -> PaginatedAlertResponse:
    """List alerts with pagination, filtering, sorting, and search."""
    params_dict = params.model_dump()
    page = params_dict.pop("page", 1)
    page_size = params_dict.pop("page_size", 25)
    search = params_dict.pop("search", None)
    status = params_dict.pop("status", None)
    severity = params_dict.pop("severity", None)
    rule_name = params_dict.pop("rule_name", None)
    start_time = params_dict.pop("start_time", None)
    end_time = params_dict.pop("end_time", None)
    sort_by = params_dict.pop("sort_by", "detected_at")
    sort_order = params_dict.pop("sort_order", "desc")

    # Validate sort params
    if sort_by not in SORTABLE_FIELDS:
        raise HTTPException(status_code=422, detail=f"Invalid sort_by. Allowed: {', '.join(SORTABLE_FIELDS.keys())}")
    if sort_order.lower() not in ("asc", "desc"):
        raise HTTPException(status_code=422, detail="sort_order must be asc or desc")

    # Build filters
    filters = []
    if status:
        filters.append(Alert.status == status)
    if severity:
        filters.append(Alert.severity == severity)
    if rule_name:
        filters.append(Alert.rule_name == rule_name)
    if start_time:
        filters.append(Alert.detected_at >= start_time)
    if end_time:
        filters.append(Alert.detected_at <= end_time)

    # Search across text fields
    if search:
        search_term = f"%{search}%"
        search_filters = or_(
            Alert.summary.ilike(f"%{search}%"),
            Alert.rule_name.ilike(f"%{search}%"),
        )
        filters.append(search_filters)

    # Build count query
    count_stmt = select(func.count()).select_from(Alert)
    if filters:
        count_stmt = count_stmt.where(and_(*filters))

    total = db.execute(count_stmt).scalar_one()
    total_pages = (total + page_size - 1) // page_size  # page_size = 25
    if page > total_pages and total > 0:
        page = total_pages

    # Build data query
    sort_col = getattr(Alert, SORTABLE_FIELDS.get(sort_by, "detected_at"))
    order = sort_col.desc() if sort_order.lower() == "desc" else sort_col.asc()

    offset = (page - 1) * page_size
    stmt = select(Alert)
    if filters:
        stmt = stmt.where(and_(*filters))
    stmt = stmt.order_by(order, Alert.id.desc()).offset(offset).limit(page_size)

    alerts = list(db.execute(stmt).scalars().all())

    return PaginatedAlertResponse(
        items=alerts,
        page=page,
        page_size=page_size,
        total=total,
        total_pages=total_pages,
    )


@router.get("/{alert_id}", response_model=AlertRead)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _to_read(alert, db)


@router.patch("/{alert_id}", response_model=AlertRead)
def update_alert(alert_id: int, payload: AlertUpdate, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if payload.status not in ("acknowledged", "resolved"):
        raise HTTPException(status_code=400, detail="Status must be acknowledged or resolved")
    # Simple lifecycle: detected -> acknowledged -> resolved
    if alert.status == "resolved":
        raise HTTPException(status_code=400, detail="Alert already resolved")
    if payload.status == "acknowledged":
        if alert.status != "detected":
            raise HTTPException(status_code=400, detail="Only detected alerts can be acknowledged")
        alert.status = "acknowledged"
        alert.acknowledged_at = datetime.now(timezone.utc)
    elif payload.status == "resolved":
        alert.status = "resolved"
        alert.resolved_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(alert)
    logger.info("Alert %s updated to %s", alert.id, alert.status)
    return _to_read(alert, db)


@router.get("/{alert_id}", response_model=AlertRead)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _to_read(alert, db)


@router.patch("/{alert_id}", response_model=AlertRead)
def update_alert(alert_id: int, payload: AlertUpdate, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if payload.status not in ("acknowledged", "resolved"):
        raise HTTPException(status_code=400, detail="Status must be acknowledged or resolved")
    # Simple lifecycle: detected -> acknowledged -> resolved
    if alert.status == "resolved":
        raise HTTPException(status_code=400, detail="Alert already resolved")
    if payload.status == "acknowledged":
        if alert.status != "detected":
            raise HTTPException(status_code=400, detail="Only detected alerts can be acknowledged")
        alert.status = "acknowledged"
        alert.acknowledged_at = datetime.now(timezone.utc)
    elif payload.status == "resolved":
        alert.status = "resolved"
        alert.resolved_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(alert)
    logger.info("Alert %s updated to %s", alert.id, alert.status)
    return _to_read(alert, db)
