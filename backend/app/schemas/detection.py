"""Detection schemas (M3)."""

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DetectionRuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: Optional[str]
    rule_type: str
    config: dict
    enabled: bool
    severity: str
    cooldown_seconds: int
    created_at: datetime
    updated_at: datetime

    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def _assume_utc(cls, value: object) -> object:
        if isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


class DetectionRuleUpdate(BaseModel):
    enabled: Optional[bool] = None


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: int
    rule_name: str
    status: str
    severity: str
    detected_at: datetime
    acknowledged_at: Optional[datetime]
    resolved_at: Optional[datetime]
    summary: str
    context: dict
    first_event_id: int
    last_event_id: int
    created_at: datetime
    updated_at: datetime
    evidence_event_ids: list[int] = Field(default_factory=list, description="Linked event IDs")

    @field_validator("detected_at", "acknowledged_at", "resolved_at", "created_at", "updated_at", mode="before")
    @classmethod
    def _assume_utc(cls, value: object) -> object:
        if isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


class AlertUpdate(BaseModel):
    status: str = Field(description="acknowledged or resolved")
    acknowledged_by: Optional[str] = None


class DetectRequest(BaseModel):
    window_seconds: int = Field(default=300, ge=1, le=86400)
    evaluation_time: Optional[datetime] = None
    rule_names: Optional[list[str]] = None

    @field_validator("evaluation_time", mode="after")
    @classmethod
    def _validate_evaluation_time(cls, value: Optional[datetime]) -> Optional[datetime]:
        if value is not None and value.tzinfo is None:
            # Reject naive datetime - require explicit timezone
            raise ValueError("evaluation_time must be timezone-aware (include timezone offset or 'Z')")
        return value


class DetectResponse(BaseModel):
    window_seconds: int
    evaluation_time: datetime
    alerts_created: int
    alerts: list[AlertRead]


class PaginatedAlertResponse(BaseModel):
    """Paginated response for alert queries (M7.4)."""

    items: list[AlertRead]
    page: int
    page_size: int
    total: int
    total_pages: int


class AlertQueryParams(BaseModel):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=25, ge=1, le=100)
    search: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    rule_name: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    sort_by: str = "detected_at"
    sort_order: str = "desc"
