"""Incidents API (M4+M7.5).

M4: Basic incident listing and status updates.
M7.5: Server-side pagination, filtering, sorting, and search for incidents.
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.db.session import get_db
from app.models.incident import Incident
from app.models.incident_alert import IncidentAlert
from app.schemas.incident import IncidentRead, IncidentUpdate, PaginatedIncidentResponse, IncidentQueryParams

router = APIRouter(prefix="/incidents", tags=["incidents"])
logger = get_logger(__name__)

# Whitelisted sortable columns for deterministic ordering
SORTABLE_FIELDS = {
    "last_seen_at": "last_seen_at",
    "first_seen_at": "first_seen_at",
    "severity": "severity",
    "status": "status",
    "id": "id",
}

# Searchable fields for text search
SEARCHABLE_FIELDS = ["title", "correlation_key"]


def _to_read(incident: Incident, db: Session) -> "IncidentRead":
    """Convert Incident model to IncidentRead with alert IDs."""
    from app.models.incident_alert import IncidentAlert
    from sqlalchemy import select as sa_select

    alert_ids = [
        row.alert_id
        for row in db.execute(
            sa_select(IncidentAlert.alert_id).where(IncidentAlert.incident_id == incident.id)
        ).all()
    ]
    data = IncidentRead.model_validate(incident)
    data.alert_ids = sorted(alert_ids)
    return data


@router.get("", response_model=PaginatedIncidentResponse)
def list_incidents(
    params: "IncidentQueryParams" = Depends(),
    db: Session = Depends(get_db),
) -> PaginatedIncidentResponse:
    """List incidents with pagination, filtering, sorting, and search."""
    params_dict = params.model_dump()
    page = params_dict.pop("page", 1)
    page_size = params_dict.pop("page_size", 25)
    search = params_dict.pop("search", None)
    status = params_dict.pop("status", None)
    severity = params_dict.pop("severity", None)
    start_time = params_dict.pop("start_time", None)
    end_time = params_dict.pop("end_time", None)
    sort_by = params_dict.pop("sort_by", "last_seen_at")
    sort_order = params_dict.pop("sort_order", "desc")

    # Validate sort params
    if sort_by not in SORTABLE_FIELDS:
        raise HTTPException(status_code=422, detail=f"Invalid sort_by. Allowed: {', '.join(SORTABLE_FIELDS.keys())}")
    if sort_order.lower() not in ("asc", "desc"):
        raise HTTPException(status_code=422, detail="sort_order must be asc or desc")

    # Build filters
    filters = []
    if status:
        filters.append(Incident.status == status)
    if severity:
        filters.append(Incident.severity == severity)
    if start_time:
        filters.append(Incident.first_seen_at >= start_time)
    if end_time:
        filters.append(Incident.last_seen_at <= end_time)

    # Search across text fields
    if search:
        search_term = f"%{search}%"
        search_filters = or_(
            Incident.title.ilike(f"%{search}%"),
            Incident.correlation_key.ilike(f"%{search}%"),
        )
        filters.append(search_filters)

    # Build count query
    count_stmt = select(func.count()).select_from(Incident)
    if filters:
        count_stmt = count_stmt.where(and_(*filters))

    total = db.execute(count_stmt).scalar_one()
    total_pages = (total + 24) // 25  # page_size = 25
    if page > total_pages and total > 0:
        page = total_pages

    # Build data query
    sort_col = getattr(Incident, SORTABLE_FIELDS.get(sort_by, "last_seen_at"))
    order = sort_col.desc() if sort_order.lower() == "desc" else sort_col.asc()

    offset = (page - 1) * 25
    stmt = select(Incident)
    if filters:
        stmt = stmt.where(and_(*filters))
    stmt = stmt.offset(offset).limit(page_size)
    incidents = list(db.execute(stmt).scalars().all())

    # Sort in Python for SQLite compatibility (deterministic, supports both asc/desc)
    reverse = sort_order.lower() == "desc"
    if sort_by in SORTABLE_FIELDS:
        key_func = lambda inc: getattr(inc, sort_by)
    else:
        key_func = lambda inc: getattr(inc, "last_seen_at")
    incidents = sorted(db.execute(stmt).scalars().all(), key=key_func, reverse=reverse)

    return PaginatedIncidentResponse(
        items=[_to_read(inc, db) for inc in incidents],
        page=page,
        page_size=25,
        total=total,
        total_pages=total_pages,
    )


@router.get("/{incident_id}", response_model=IncidentRead)
def get_incident(incident_id: int, db: Session = Depends(get_db)) -> IncidentRead:
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _to_read(inc, db)


@router.patch("/{incident_id}", response_model=IncidentRead)
def update_incident(incident_id: int, payload: IncidentUpdate, db: Session = Depends(get_db)) -> IncidentRead:
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    new_status = payload.status
    # Valid transitions: open -> investigating, investigating -> resolved
    if inc.status == "open" and new_status == "investigating":
        inc.status = new_status
    elif inc.status == "investigating" and new_status == "resolved":
        inc.status = new_status
    else:
        raise HTTPException(status_code=400, detail=f"Invalid transition {inc.status} -> {new_status}")
    db.commit()
    db.refresh(inc)
    logger.info("Incident %s updated to %s", inc.id, inc.status)
    return _to_read(inc, db)