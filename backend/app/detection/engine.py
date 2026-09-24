"""DetectionEngine (M3)."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import select

from app.models.event import Event
from app.models.detection_rule import DetectionRule
from app.detection.base import EvaluationContext
from app.detection.registry import rule_registry


class DetectionEngine:
    """Scans recent events against enabled rules.

    Deterministic evaluation_time supported.
    """

    def scan_recent(
        self,
        db: Session,
        window_seconds: int = 300,
        evaluation_time: Optional[datetime] = None,
        rule_names: Optional[list[str]] = None,
    ) -> list[dict]:
        """Scan events in [evaluation_time - window, evaluation_time].

        Returns list of dicts describing matches (rule, group_key, evidence ids, etc.)
        Actual Alert creation is handled by DetectionService.
        """
        if evaluation_time is None:
            evaluation_time = datetime.now(timezone.utc)
        if evaluation_time.tzinfo is None:
            evaluation_time = evaluation_time.replace(tzinfo=timezone.utc)

        # Load relevant events once (all in window, filter further per rule)
        # Use inclusive window for query too
        from datetime import timedelta

        cutoff = evaluation_time - timedelta(seconds=window_seconds)
        stmt = select(Event).where(Event.timestamp >= cutoff).where(Event.timestamp <= evaluation_time)
        all_window_events = list(db.execute(stmt).scalars().all())

        # Determine which rules to evaluate
        if rule_names is not None:
            rules_to_check = [r for n in rule_names if (r := rule_registry.get(n)) is not None]
        else:
            rules_to_check = rule_registry.get_all()

        # Also fetch DetectionRule models for metadata (severity, cooldown, etc.)
        results = []
        for rule in rules_to_check:
            # Find corresponding DetectionRule model for config
            # Rule instances are registered with name matching DB name
            rule_model = db.execute(select(DetectionRule).where(DetectionRule.name == rule.name)).scalars().first()
            if rule_model is None:
                continue
            if not rule_model.enabled:
                continue
            # Sync instance config with DB config (allows runtime config changes)
            rule.config = rule_model.config
            ctx = EvaluationContext(
                window_events=all_window_events,
                evaluation_time=evaluation_time,
                window_seconds=window_seconds,
                rule_config=rule_model.config,
                db=db,
            )
            matches = rule.evaluate(ctx)
            for m in matches:
                results.append(
                    {
                        "rule": rule,
                        "rule_model": rule_model,
                        "match": m,
                    }
                )
        return results
