"""BaseRule, RuleMatch, EvaluationContext (M3)."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.models.event import Event


@dataclass
class EvaluationContext:
    """Context passed to rules during evaluation."""

    # All events within the time window (already filtered by time)
    window_events: list[Event]
    evaluation_time: datetime
    window_seconds: int
    rule_config: dict
    db: Session


@dataclass
class RuleMatch:
    """Result of a rule that matched."""

    group_key: str
    context: dict
    evidence_event_ids: list[int]
    summary: str


class BaseRule(ABC):
    """Abstract deterministic detection rule."""

    # Must match DetectionRule.name in DB conceptually, but class defines default name
    name: str = "base"
    # Must match DetectionRule.rule_type conceptually
    rule_type: str = "base"
    default_config: dict = {}

    def __init__(self, config: Optional[dict] = None):
        self.config = config or self.default_config

    def get_config_value(self, key: str, default=None):
        return self.config.get(key, self.default_config.get(key, default))

    @abstractmethod
    def evaluate(self, ctx: EvaluationContext) -> list[RuleMatch]:
        """Evaluate rule against window_events.

        Returns list of RuleMatch (0 or more groups matched).
        """
        pass
