"""BruteForceLoginRule (M3)."""

from app.detection.base import BaseRule, EvaluationContext, RuleMatch
from app.detection.helpers import (
    filter_events,
    get_time_window,
    group_events_by_path,
    looks_like_auth_failure,
)


class BruteForceLoginRule(BaseRule):
    """5+ failed logins from same IP within 60 seconds.

    Default config: threshold=5, window_seconds=60, group_by="extra_data.ip", filter={"level": "ERROR"}

    Beyond the configured filter, WARNING/CRITICAL events whose message
    carries explicit auth-failure signals are also counted: real-world auth
    systems commonly log failed logins at WARNING (e.g. syslog-style
    `WARN auth.service Failed login attempt ...`). INFO-level lines never
    count. This extension lives in code (not stored config) so it applies
    to databases seeded before it existed.
    """

    name = "BruteForceLogin"
    rule_type = "threshold"
    default_config = {
        "threshold": 5,
        "window_seconds": 60,
        "group_by": "extra_data.ip",
        "filter": {"level": "ERROR"},
    }

    def evaluate(self, ctx: EvaluationContext) -> list[RuleMatch]:
        threshold = int(ctx.rule_config.get("threshold", self.default_config["threshold"]))
        window_seconds = int(ctx.rule_config.get("window_seconds", self.default_config["window_seconds"]))
        group_by = str(ctx.rule_config.get("group_by", self.default_config["group_by"]))
        filters = ctx.rule_config.get("filter", self.default_config.get("filter"))

        # 1. Time window inclusive
        windowed = get_time_window(ctx.window_events, window_seconds, ctx.evaluation_time)
        # 2. Apply filters
        filtered = filter_events(windowed, filters)
        # 2b. Include WARNING/CRITICAL auth-failure messages (see docstring).
        seen = {id(e) for e in filtered}
        candidates = list(filtered)
        for e in windowed:
            if id(e) not in seen and looks_like_auth_failure(e):
                seen.add(id(e))
                candidates.append(e)
        # 3. Group
        groups = group_events_by_path(candidates, group_by)

        matches: list[RuleMatch] = []
        for group_key, evs in groups.items():
            if len(evs) >= threshold:
                ev_ids = sorted(e.id for e in evs)
                matches.append(
                    RuleMatch(
                        group_key=group_key,
                        context={
                            "group_key": group_key,
                            "count": len(evs),
                            "threshold": threshold,
                            "window_seconds": window_seconds,
                            "group_by": group_by,
                        },
                        evidence_event_ids=ev_ids,
                        summary=f"{len(evs)} failed logins from {group_key} in {window_seconds}s (threshold {threshold})",
                    )
                )
        return matches
