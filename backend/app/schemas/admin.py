"""Admin schemas — dev data reset (no migration, data-only operation)."""

from pydantic import BaseModel, Field


class ResetRequest(BaseModel):
    """Explicit confirmation guard. Must be exactly "RESET"."""

    confirm: str = Field(description='Type "RESET" to confirm deletion')


class ResetResponse(BaseModel):
    """Counts of deleted pipeline rows. Detection rules are preserved."""

    events_deleted: int
    alerts_deleted: int
    incidents_deleted: int
    alert_events_deleted: int
    incident_alerts_deleted: int
