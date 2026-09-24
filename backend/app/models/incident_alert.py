"""IncidentAlert association table (M4)."""

from sqlalchemy import ForeignKey, Index, Integer, PrimaryKeyConstraint, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class IncidentAlert(Base):
    """Join table: incident -> alert. Enforces one incident per alert via UNIQUE(alert_id)."""

    __tablename__ = "incident_alerts"

    __table_args__ = (
        PrimaryKeyConstraint("incident_id", "alert_id", name="pk_incident_alert"),
        UniqueConstraint("alert_id", name="uq_incident_alert_alert_id"),
        Index("ix_incident_alerts_alert_id", "alert_id"),
        Index("ix_incident_alerts_incident_id", "incident_id"),
    )

    incident_id: Mapped[int] = mapped_column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    alert_id: Mapped[int] = mapped_column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)

    incident: Mapped["Incident"] = relationship(back_populates="incident_alerts")  # type: ignore[name-defined]
    alert: Mapped["Alert"] = relationship()  # type: ignore[name-defined]
