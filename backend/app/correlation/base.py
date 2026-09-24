"""Strategy ABC (M4)."""

from abc import ABC, abstractmethod
from typing import Optional

from sqlalchemy.orm import Session

from app.models.alert import Alert


class CorrelationStrategy(ABC):
    """Pure deterministic extraction/grouping. No DB writes."""

    name: str = "base"

    @abstractmethod
    def extract_key(self, alert: Alert, db: Session) -> Optional[str]:
        """Return correlation_key or None if alert should be skipped.

        Must be deterministic and handle ambiguous/missing cases.
        """
        pass

    def group(self, alerts: list[Alert], db: Session) -> dict[str, list[Alert]]:
        """Group alerts by extracted key. Skipped alerts omitted."""
        groups: dict[str, list[Alert]] = {}
        for alert in alerts:
            key = self.extract_key(alert, db)
            if key is None:
                continue
            groups.setdefault(key, []).append(alert)
        return groups
