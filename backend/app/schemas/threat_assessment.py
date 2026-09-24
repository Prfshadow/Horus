"""Threat Assessment schemas."""

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ThreatAssessmentRequest(BaseModel):
    """Request to run threat assessment on recent events."""

    window_seconds: int = Field(default=300, ge=1, le=86400, description="Detection window in seconds")
    correlation_window_seconds: int = Field(default=3600, ge=1, le=86400, description="Correlation window in seconds")
    evaluation_time: Optional[datetime] = Field(default=None, description="Explicit evaluation time (UTC). If omitted, uses current time — or, when event_ids are given, the newest referenced event.")
    correlation_strategy: str = Field(default="source_ip", description="Correlation strategy: source_ip or host")
    rule_names: Optional[list[str]] = Field(default=None, description="Optional subset of rule names to evaluate")
    synthetic: bool = Field(default=False, description="Whether the input data is synthetic/demo")
    event_ids: Optional[list[int]] = Field(
        default=None,
        description="Optional scope: assess only the given ingested events. "
        "Anchors evaluation_time at the newest referenced event so uploads with "
        "their own timestamps are analyzed regardless of the server clock.",
    )

    @field_validator("evaluation_time", mode="after")
    @classmethod
    def _validate_evaluation_time(cls, value: Optional[datetime]) -> Optional[datetime]:
        if value is not None and value.tzinfo is None:
            raise ValueError("evaluation_time must be timezone-aware (include timezone offset or 'Z')")
        return value

    @field_validator("correlation_strategy")
    @classmethod
    def _validate_strategy(cls, value: str) -> str:
        if value not in ("source_ip", "host"):
            raise ValueError("correlation_strategy must be 'source_ip' or 'host'")
        return value

    @field_validator("event_ids", mode="after")
    @classmethod
    def _validate_event_ids(cls, value: Optional[list[int]]) -> Optional[list[int]]:
        if value is None:
            return None
        if len(value) > 10000:
            raise ValueError("event_ids must contain at most 10000 entries")
        if any(not isinstance(i, int) or isinstance(i, bool) or i < 1 for i in value):
            raise ValueError("event_ids must be positive integer event IDs")
        return value


class ThreatAssessmentResponse(BaseModel):
    """Response from threat assessment."""

    threat_level: str = Field(description="Overall threat level: LOW, MEDIUM, HIGH, CRITICAL")
    threat_title: str = Field(description="Short title summarizing the threat")
    explanation: str = Field(description="Human-readable explanation of what was detected")
    details: list[str] = Field(description="Bullet-point details of what was detected")
    alerts_count: int = Field(description="Total alerts generated")
    incidents_count: int = Field(description="Total incidents created/correlated")
    events_analyzed: int = Field(description="Number of events analyzed")
    alert_severities: dict[str, int] = Field(description="Alert count by severity")
    incident_severities: dict[str, int] = Field(description="Incident count by severity")
    affected_entities: dict[str, list[str]] = Field(description="Affected IPs, hosts, users")
    synthetic: bool = Field(description="Whether the assessment was on synthetic data")
    alert_ids: list[int] = Field(default_factory=list, description="IDs of alerts created in this run")
    incident_ids: list[int] = Field(default_factory=list, description="IDs of incidents linked to this run's alerts")

    model_config = ConfigDict(from_attributes=True)