"""Alert model (M3).

Alert represents a rule match, with lifecycle: detected -> acknowledged -> resolved
Evidence via AlertEvent join table.
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Alert(Base):
    """Persistent detection finding."""

    __tablename__ = "alerts"

    __table_args__ = (
        Index("ix_alerts_rule_id", "rule_id"),
        Index("ix_alerts_status", "status"),
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_detected_at", "detected_at"),
        Index("ix_alerts_first_event_id", "first_event_id"),
        Index("ix_alerts_last_event_id", "last_event_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[int] = mapped_column(Integer, ForeignKey("detection_rules.id"), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(128), nullable=False)
    # detected, acknowledged, resolved
    status: Mapped[str] = mapped_column(String(32), default="detected", nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Human-readable summary, e.g. "5 failed logins from 10.0.0.5 in 60s"
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    # Structured context: {group_key, count, window_seconds, ...}
    context: Mapped[dict] = mapped_column(JSON, nullable=False)
    first_event_id: Mapped[int] = mapped_column(Integer, nullable=False)
    last_event_id: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    rule: Mapped["DetectionRule"] = relationship(back_populates="alerts")  # type: ignore[name-defined]
    evidence_links: Mapped[list["AlertEvent"]] = relationship(  # type: ignore[name-defined]
        back_populates="alert", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"Alert(id={self.id!r}, rule_name={self.rule_name!r}, status={self.status!r})"
