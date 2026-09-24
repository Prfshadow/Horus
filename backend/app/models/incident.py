"""Incident model (M4)."""

from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Incident(Base):
    """Investigation container for related alerts."""

    __tablename__ = "incidents"

    __table_args__ = (
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_correlation_key", "correlation_key"),
        Index("ix_incidents_last_seen_at", "last_seen_at"),
        Index("ix_incidents_severity", "severity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    # open -> investigating -> resolved (human only)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    # deterministic key from strategy, e.g. "ip:10.0.0.5" or "host:server-01"
    correlation_key: Mapped[str] = mapped_column(String(256), nullable=False)
    # audit: {strategy, correlation_window_seconds, correlation_key}
    context: Mapped[dict] = mapped_column(JSON, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    incident_alerts: Mapped[list["IncidentAlert"]] = relationship(  # type: ignore[name-defined]
        back_populates="incident", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"Incident(id={self.id!r}, key={self.correlation_key!r}, status={self.status!r})"
