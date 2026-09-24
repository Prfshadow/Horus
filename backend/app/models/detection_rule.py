"""DetectionRule model (M3).

Stores deterministic detection rule configuration.
Rule logic lives in Python classes; this table stores thresholds, windows, etc.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class DetectionRule(Base):
    """Configuration for a deterministic detection rule."""

    __tablename__ = "detection_rules"

    __table_args__ = (
        Index("ix_detection_rules_enabled", "enabled"),
        Index("ix_detection_rules_name", "name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # rule_type maps to Python class: threshold -> BruteForceLoginRule, frequency -> ErrorSpikeRule
    rule_type: Mapped[str] = mapped_column(String(64), nullable=False)
    # Portable JSON: SQLite TEXT, PostgreSQL JSONB
    config: Mapped[dict] = mapped_column(JSON, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM", nullable=False)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    alerts: Mapped[list["Alert"]] = relationship(back_populates="rule", cascade="all, delete-orphan")  # type: ignore[name-defined]

    def __repr__(self) -> str:
        return f"DetectionRule(id={self.id!r}, name={self.name!r}, enabled={self.enabled!r})"
