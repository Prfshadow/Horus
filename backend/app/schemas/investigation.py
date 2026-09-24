"""Investigation schemas (M5)."""

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _assume_utc(v: object) -> object:
    if isinstance(v, datetime) and v.tzinfo is None:
        return v.replace(tzinfo=timezone.utc)
    return v


class InvestigationIncident(BaseModel):
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

    @field_validator("first_seen_at", "last_seen_at", "created_at", "updated_at", mode="before")
    @classmethod
    def _utc(cls, v: object) -> object:
        return _assume_utc(v)


class InvestigationAlert(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    rule_id: int
    rule_name: str
    rule_type: Optional[str] = None
    severity: str
    status: str
    detected_at: datetime
    summary: str
    context: dict
    first_event_id: int
    last_event_id: int
    evidence_event_ids: list[int] = Field(default_factory=list)

    @field_validator("detected_at", mode="before")
    @classmethod
    def _utc2(cls, v: object) -> object:
        return _assume_utc(v)


class InvestigationEvent(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    timestamp: datetime
    ingested_at: datetime
    source: str
    level: str
    service: Optional[str]
    host: Optional[str]
    message: str
    raw_log: str
    extra_data: Optional[dict] = None

    @field_validator("timestamp", "ingested_at", mode="before")
    @classmethod
    def _utc3(cls, v: object) -> object:
        return _assume_utc(v)


class TimelineEntry(BaseModel):
    type: str = Field(description="event or alert")
    id: int
    timestamp: datetime
    summary: str

    @field_validator("timestamp", mode="before")
    @classmethod
    def _utc4(cls, v: object) -> object:
        return _assume_utc(v)


class InvestigationCorrelation(BaseModel):
    strategy: str
    correlation_key: str
    correlation_window_seconds: int


class InvestigationSummary(BaseModel):
    alert_count: int
    event_count: int
    unique_sources: int
    unique_hosts: int
    unique_services: int
    severity_breakdown: dict[str, int]
    time_span_seconds: int
    total_alert_count: int
    total_event_count: int
    truncated: bool


class InvestigationEntities(BaseModel):
    ips: list[str]
    hosts: list[str]
    services: list[str]
    sources: list[str]


class InvestigationDetection(BaseModel):
    alert_id: int
    rule_id: int
    rule_name: str
    rule_type: Optional[str]
    severity: str
    summary: str
    context: dict


class InvestigationContextResponse(BaseModel):
    incident: InvestigationIncident
    alerts: list[InvestigationAlert]
    events: list[InvestigationEvent]
    timeline: list[TimelineEntry]
    correlation: InvestigationCorrelation
    summary: InvestigationSummary
    entities: InvestigationEntities
    detection: list[InvestigationDetection]
