"""IncidentCorrelationEngine (M4)."""

from typing import Optional

from sqlalchemy.orm import Session

from app.correlation.base import CorrelationStrategy
from app.correlation.strategies.source_ip import SourceIpStrategy
from app.correlation.strategies.host import HostStrategy
from app.models.alert import Alert


class IncidentCorrelationEngine:
    """Selects ONE strategy, groups alerts deterministically. No DB writes."""

    def __init__(self, strategies: Optional[dict[str, CorrelationStrategy]] = None):
        if strategies is None:
            strategies = {
                "source_ip": SourceIpStrategy(),
                "host": HostStrategy(),
            }
        self.strategies = strategies

    def correlate(
        self, alerts: list[Alert], strategy_name: str, db: Session
    ) -> dict[str, list[Alert]]:
        """Group alerts by requested strategy. Returns {correlation_key: [alerts]}."""
        strat = self.strategies.get(strategy_name)
        if not strat:
            raise ValueError(f"Unknown strategy: {strategy_name}")
        # Ensure deterministic input order: sort by detected_at ASC, id ASC before grouping
        sorted_alerts = sorted(alerts, key=lambda a: (a.detected_at, a.id))
        return strat.group(sorted_alerts, db)
