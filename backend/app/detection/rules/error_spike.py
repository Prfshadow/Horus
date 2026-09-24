"""ErrorSpikeRule (M3)."""

from app.detection.base import BaseRule, EvaluationContext, RuleMatch
from app.detection.helpers import filter_events, get_time_window, group_events_by_path


class ErrorSpikeRule(BaseRule):
    """ERROR rate spike per group.

    Alerts when count >= min_events AND rate_per_minute >= rate_threshold.
    Default: min_events=10, window_seconds=300, rate_threshold=20/min, group_by="service"
    """

    name = "ErrorSpike"
    rule_type = "frequency"
    default_config = {
        "min_events": 10,
        "window_seconds": 300,
        "rate_threshold": 20,
        "group_by": "service",
        "filter": {"level": "ERROR"},
    }

    def evaluate(self, ctx: EvaluationContext) -> list[RuleMatch]:
        min_events = int(ctx.rule_config.get("min_events", self.default_config["min_events"]))
        window_seconds = int(ctx.rule_config.get("window_seconds", self.default_config["window_seconds"]))
        rate_threshold = float(ctx.rule_config.get("rate_threshold", self.default_config["rate_threshold"]))
        group_by = str(ctx.rule_config.get("group_by", self.default_config["group_by"]))
        filters = ctx.rule_config.get("filter", self.default_config.get("filter"))

        windowed = get_time_window(ctx.window_events, window_seconds, ctx.evaluation_time)
        filtered = filter_events(windowed, filters)
        groups = group_events_by_path(filtered, group_by)

        matches: list[RuleMatch] = []
        for group_key, evs in groups.items():
            count = len(evs)
            if count < min_events:
                continue
            rate_per_minute = count / (window_seconds / 60.0)
            if rate_per_minute >= rate_threshold:
                ev_ids = sorted(e.id for e in evs)
                matches.append(
                    RuleMatch(
                        group_key=group_key,
                        context={
                            "group_key": group_key,
                            "count": count,
                            "min_events": min_events,
                            "rate_per_minute": round(rate_per_minute, 2),
                            "rate_threshold": rate_threshold,
                            "window_seconds": window_seconds,
                            "group_by": group_by,
                        },
                        evidence_event_ids=ev_ids,
                        summary=f"Error spike for {group_key}: {count} events in {window_seconds}s ({rate_per_minute:.1f}/min >= {rate_threshold}/min)",
                    )
                )
        return matches
