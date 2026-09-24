"""Stats schemas (M7.2) — deterministic aggregates for dashboard."""

from datetime import datetime, timezone
from typing import Dict

from pydantic import BaseModel, Field


class StatsEvents(BaseModel):
    total: int = Field(description="All events currently stored (all time)")


class StatsAlerts(BaseModel):
    total: int = Field(description="All alerts (all time)")
    active: int = Field(description="Alerts with status detected or acknowledged")
    by_severity: Dict[str, int] = Field(description="Count by severity LOW/MEDIUM/HIGH/CRITICAL")
    by_status: Dict[str, int] = Field(description="Count by status detected/acknowledged/resolved")


class StatsIncidents(BaseModel):
    total: int = Field(description="All incidents (all time)")
    open: int = Field(description="Incidents with status open")
    investigating: int = Field(description="Incidents with status investigating")
    resolved: int = Field(description="Incidents with status resolved")
    by_severity: Dict[str, int] = Field(description="Count by severity")


class StatsResponse(BaseModel):
    events: StatsEvents
    alerts: StatsAlerts
    incidents: StatsIncidents
    generated_at: datetime = Field(description="When stats were computed (UTC)")
