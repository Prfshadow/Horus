"""Canonical normalized log Event (M1).

Design notes (approved plan):
- `timestamp`  = when the event HAPPENED (from the log source).
- `ingested_at` = when HORUS stored it (server-side, never client-controlled).
- `raw_log` is stored verbatim and never modified (enables re-parsing).
- Fixed indexed columns for filtering + nullable `extra_data` JSON for the rest.
- Only portable SQLAlchemy types are used so the model works on both
  SQLite (M1 dev) and PostgreSQL (later) without changes.
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Event(Base):
    """A single normalized log event."""

    __tablename__ = "events"

    __table_args__ = (
        Index("ix_events_timestamp", "timestamp"),
        Index("ix_events_source", "source"),
        Index("ix_events_level", "level"),
        Index("ix_events_service", "service"),
        Index("ix_events_host", "host"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # When the event happened (client-provided, timezone-aware UTC).
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # When HORUS ingested it (server-set, timezone-aware UTC).
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Where the log came from, e.g. "auth-service", "nginx-access".
    source: Mapped[str] = mapped_column(String(255), nullable=False)

    # Normalized severity, e.g. DEBUG/INFO/WARNING/ERROR/CRITICAL.
    level: Mapped[str] = mapped_column(String(32), nullable=False, default="INFO")

    service: Mapped[str | None] = mapped_column(String(255), nullable=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)

    message: Mapped[str] = mapped_column(Text, nullable=False)

    # Original log line, verbatim. Never transformed.
    raw_log: Mapped[str] = mapped_column(Text, nullable=False)

    # Flexible remainder, e.g. {"ip": "...", "status": 500}. NULL when empty.
    extra_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    def __repr__(self) -> str:
        return (
            f"Event(id={self.id!r}, timestamp={self.timestamp!r}, "
            f"source={self.source!r}, level={self.level!r})"
        )
