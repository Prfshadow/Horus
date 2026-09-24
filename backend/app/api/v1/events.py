"""Event endpoints (M1-M7.3).

M7.3 adds server-side search, filtering, sorting and pagination.
Raw log is stored verbatim; sorting and filtering are whitelisted.
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.db.session import get_db
from app.models.event import Event
from app.schemas.event import EventCreate, EventRead, PaginatedEventResponse

router = APIRouter(prefix="/events", tags=["events"])
logger = get_logger(__name__)

# Whitelisted sortable columns — prevents arbitrary SQL/order injection
SORTABLE_FIELDS = {
    "timestamp": Event.timestamp,
    "ingested_at": Event.ingested_at,
    "id": Event.id,
    "level": Event.level,
    "source": Event.source,
    "service": Event.service,
    "host": Event.host,
}


@router.post("", response_model=EventRead, status_code=status.HTTP_201_CREATED)
def create_event(payload: EventCreate, db: Session = Depends(get_db)) -> Event:
    """Store a single normalized event."""
    event = Event(
        timestamp=payload.timestamp,
        source=payload.source,
        level=payload.level,
        service=payload.service,
        host=payload.host,
        message=payload.message,
        raw_log=payload.raw_log,  # verbatim, never transformed
        extra_data=payload.extra_data,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    logger.info("Stored event id=%s source=%s level=%s", event.id, event.source, event.level)
    return event


@router.get("", response_model=PaginatedEventResponse)
def list_events(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=50, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(default=None, description="Search in message/source/service/host"),
    level: Optional[str] = Query(default=None, description="Filter by level"),
    source: Optional[str] = Query(default=None, description="Filter by source"),
    service: Optional[str] = Query(default=None, description="Filter by service"),
    host: Optional[str] = Query(default=None, description="Filter by host"),
    start_time: Optional[datetime] = Query(default=None, description="Filter timestamp >= start_time (UTC)"),
    end_time: Optional[datetime] = Query(default=None, description="Filter timestamp <= end_time (UTC)"),
    sort_by: str = Query(default="timestamp", description="Sort field"),
    sort_order: str = Query(default="desc", description="Sort order asc/desc"),
    # Backward-compat: old `limit` param (M1) — if provided without page/page_size change, treat as page_size
    limit: Optional[int] = Query(default=None, ge=1, le=200, description="Legacy limit (deprecated)"),
    db: Session = Depends(get_db),
) -> PaginatedEventResponse:
    """List events with server-side search, filtering, sorting and pagination."""
    # Handle legacy limit param
    if limit is not None and page == 1 and page_size == 50:
        # Old client used ?limit=10 — treat as page_size
        page_size = max(1, min(limit, 100))
        page = 1

    # Validate sort params
    sort_by = sort_by.strip()
    sort_order = sort_order.strip().lower()
    if sort_by not in SORTABLE_FIELDS:
        raise HTTPException(status_code=422, detail=f"Invalid sort_by. Allowed: {', '.join(SORTABLE_FIELDS.keys())}")
    if sort_order not in ("asc", "desc"):
        raise HTTPException(status_code=422, detail="sort_order must be asc or desc")

    # Build filters
    filters = []
    if search:
        pattern = f"%{search}%"
        # Use ilike for case-insensitive search on text fields (portable SQLite/PostgreSQL)
        filters.append(
            or_(
                Event.message.ilike(pattern),
                Event.source.ilike(pattern),
                Event.service.ilike(pattern),
                Event.host.ilike(pattern),
            )
        )
    if level:
        filters.append(Event.level == level)
    if source:
        filters.append(Event.source == source)
    if service:
        filters.append(Event.service == service)
    if host:
        filters.append(Event.host == host)
    if start_time:
        # Ensure timezone-aware (assume UTC if naive)
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        filters.append(Event.timestamp >= start_time)
    if end_time:
        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)
        filters.append(Event.timestamp <= end_time)

    # Count total with filters
    count_stmt = select(func.count()).select_from(Event)
    if filters:
        count_stmt = count_stmt.where(and_(*filters))
    total = db.execute(count_stmt).scalar_one()

    total_pages = (total + page_size - 1) // page_size if total > 0 else 1
    # Clamp page to total_pages (return empty items if beyond)
    if page > total_pages:
        items: list[Event] = []
    else:
        sort_col = SORTABLE_FIELDS[sort_by]
        order = sort_col.desc() if sort_order == "desc" else sort_col.asc()
        # Deterministic secondary sort by id desc to ensure stable ordering
        secondary = Event.id.desc() if sort_order == "desc" else Event.id.asc()
        stmt = select(Event)
        if filters:
            stmt = stmt.where(and_(*filters))
        stmt = stmt.order_by(order, secondary).offset((page - 1) * page_size).limit(page_size)
        items = list(db.execute(stmt).scalars().all())

    return PaginatedEventResponse(
        items=items,  # Pydantic will validate via EventRead
        page=page,
        page_size=page_size,
        total=total,
        total_pages=total_pages,
    )


@router.get("/{event_id}", response_model=EventRead)
def get_event(event_id: int, db: Session = Depends(get_db)) -> Event:
    """Get single event by ID."""
    event = db.get(Event, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
