"""Pydantic schemas for Event API validation (M1).

- `EventCreate`: what clients may send. `ingested_at` is deliberately
  absent — the server sets it so ingestion time is trustworthy.
- `EventRead`: what the API returns, including server-assigned fields.
"""

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventCreate(BaseModel):
    """Payload for creating a normalized event."""

    timestamp: datetime = Field(
        description="When the event happened (UTC, from the log source)."
    )
    source: str = Field(min_length=1, max_length=255)
    level: str = Field(default="INFO", min_length=1, max_length=32)
    service: str | None = Field(default=None, max_length=255)
    host: str | None = Field(default=None, max_length=255)
    message: str = Field(min_length=1)
    raw_log: str = Field(min_length=0, description="Original log line, verbatim.")
    extra_data: dict | None = None


class EventRead(BaseModel):
    """Event as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    ingested_at: datetime
    source: str
    level: str
    service: str | None
    host: str | None
    message: str
    raw_log: str
    extra_data: dict | None

    @field_validator("timestamp", "ingested_at", mode="before")
    @classmethod
    def _assume_utc_if_naive(cls, value: object) -> object:
        """Treat naive datetimes from SQLite as UTC.

        PostgreSQL preserves tzinfo; SQLite does not. All HORUS times are UTC,
        so a naive value can only mean "UTC without marker".
        """
        if isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


class PaginatedEventResponse(BaseModel):
    """Paginated response for event queries (M7.3)."""

    items: list[EventRead]
    page: int
    page_size: int
    total: int
    total_pages: int
