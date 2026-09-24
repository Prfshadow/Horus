"""AlertEvent association table (M3).

Links alerts to evidence events via foreign keys.
Composite PK ensures uniqueness.
"""

from sqlalchemy import ForeignKey, Index, Integer, PrimaryKeyConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AlertEvent(Base):
    """Join table: alert -> event evidence."""

    __tablename__ = "alert_events"

    __table_args__ = (
        PrimaryKeyConstraint("alert_id", "event_id", name="pk_alert_event"),
        Index("ix_alert_events_event_id", "event_id"),
    )

    alert_id: Mapped[int] = mapped_column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    event_id: Mapped[int] = mapped_column(Integer, ForeignKey("events.id", ondelete="CASCADE"), nullable=False)

    alert: Mapped["Alert"] = relationship(back_populates="evidence_links")  # type: ignore[name-defined]
    event: Mapped["Event"] = relationship()  # type: ignore[name-defined]

    def __repr__(self) -> str:
        return f"AlertEvent(alert_id={self.alert_id!r}, event_id={self.event_id!r})"
