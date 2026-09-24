"""Incident schemas (M4+M7.5)."""

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    status: str
    severity: str
    correlation_key: str
    context: dict
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime
    alert_ids: list[int] = Field(default_factory=list)

    @field_validator("first_seen_at", "last_seen_at", "created_at", "updated_at", mode="before")
    @classmethod
    def _assume_utc(cls, value: object) -> object:
        if isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


class IncidentUpdate(BaseModel):
    status: str = Field(description="investigating or resolved")


class PaginatedIncidentResponse(BaseModel):
    """Paginated response for incident queries (M7.5)."""

    items: list["IncidentRead"]
    page: int
    page_size: int
    total: int
    total_pages: int


class IncidentQueryParams(BaseModel):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=25, ge=1, le=100)
    status: Optional[str] = None
    severity: Optional[str] = None
    search: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    sort_by: str = "last_seen_at"
    sort_order: str = "desc"


class CorrelateRequest(BaseModel):
    window_seconds: int = Field(default=3600, ge=1, le=86400)
    evaluation_time: Optional[datetime] = None
    strategy: str = Field(default="source_ip", description="source_ip or host")
    rule_names: Optional[list[str]] = None

    @field_validator("strategy")
    @classmethod
    def _validate_strategy(cls, v: str) -> str:
        if v not in ("source_ip", "host"):
            raise ValueError("strategy must be source_ip or host")
        return v


class CorrelateResponse(BaseModel):
    window_seconds: int
    evaluation_time: datetime
    strategy: str
    incidents_created: int
    incidents_updated: int
    alerts_correlated: int
    incidents: list[IncidentRead]
