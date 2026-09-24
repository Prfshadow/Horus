"""Tests for ErrorSpikeRule (M3)."""

from datetime import datetime, timedelta, timezone

from app.detection.rules.error_spike import ErrorSpikeRule
from app.detection.base import EvaluationContext
from app.models.event import Event


def make_event(id_: int, ts: datetime, service: str, level: str = "ERROR") -> Event:
    e = Event(
        timestamp=ts,
        source="app",
        level=level,
        service=service,
        message="error",
        raw_log="raw",
        extra_data={},
    )
    e.id = id_  # type: ignore
    return e


class TestErrorSpikeRule:
    def setup_method(self):
        self.rule = ErrorSpikeRule()

    def test_below_min_events_no_alert(self):
        now = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        # min_events=10, only 9
        evs = [make_event(i, now - timedelta(seconds=i * 10), "api") for i in range(9)]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=300, rule_config=self.rule.default_config, db=None)  # type: ignore
        matches = self.rule.evaluate(ctx)
        assert len(matches) == 0

    def test_rate_below_threshold_no_alert(self):
        now = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        # 10 events in 300s => 2/min < 20 threshold
        evs = [make_event(i, now - timedelta(seconds=i * 20), "api") for i in range(10)]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=300, rule_config=self.rule.default_config, db=None)  # type: ignore
        matches = self.rule.evaluate(ctx)
        assert len(matches) == 0

    def test_rate_exact_threshold_triggers(self):
        now = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        # window 60s, rate 10/min, 10 events in 60s => 10/min meets threshold
        config = {"min_events": 10, "window_seconds": 60, "rate_threshold": 10, "group_by": "service", "filter": {"level": "ERROR"}}
        evs = [make_event(i, now - timedelta(seconds=i * 5), "api") for i in range(10)]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=60, rule_config=config, db=None)  # type: ignore
        rule = ErrorSpikeRule(config=config)
        matches = rule.evaluate(ctx)
        assert len(matches) == 1
        assert matches[0].group_key == "api"

    def test_and_condition_both_required(self):
        now = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        # 30 events in 300s => 6/min > 5 threshold, and count >=10 => should trigger if both AND
        config = {"min_events": 10, "window_seconds": 300, "rate_threshold": 5, "group_by": "service", "filter": {"level": "ERROR"}}
        evs = [make_event(i, now - timedelta(seconds=i * 8), "api") for i in range(30)]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=300, rule_config=config, db=None)  # type: ignore
        rule = ErrorSpikeRule(config=config)
        matches = rule.evaluate(ctx)
        assert len(matches) == 1

        # If we have many events but rate low due to large window, should not trigger
        config2 = {"min_events": 10, "window_seconds": 600, "rate_threshold": 20, "group_by": "service", "filter": {"level": "ERROR"}}
        evs2 = [make_event(i, now - timedelta(seconds=i * 30), "api") for i in range(15)]  # 15 in 600s => 1.5/min <20
        ctx2 = EvaluationContext(window_events=evs2, evaluation_time=now, window_seconds=600, rule_config=config2, db=None)  # type: ignore
        rule2 = ErrorSpikeRule(config=config2)
        matches2 = rule2.evaluate(ctx2)
        assert len(matches2) == 0

    def test_group_by_service_isolates(self):
        now = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        config = {"min_events": 3, "window_seconds": 60, "rate_threshold": 3, "group_by": "service", "filter": {"level": "ERROR"}}
        evs_api = [make_event(i, now - timedelta(seconds=i * 10), "api") for i in range(5)]
        evs_auth = [make_event(i + 10, now - timedelta(seconds=i * 10), "auth") for i in range(2)]
        ctx = EvaluationContext(window_events=evs_api + evs_auth, evaluation_time=now, window_seconds=60, rule_config=config, db=None)  # type: ignore
        rule = ErrorSpikeRule(config=config)
        matches = rule.evaluate(ctx)
        assert len(matches) == 1
        assert matches[0].group_key == "api"

    def test_window_inclusive(self):
        now = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        config = {"min_events": 2, "window_seconds": 60, "rate_threshold": 2, "group_by": "service", "filter": {"level": "ERROR"}}
        cutoff = now - timedelta(seconds=60)
        evs = [make_event(0, cutoff, "api"), make_event(1, now, "api")]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=60, rule_config=config, db=None)  # type: ignore
        rule = ErrorSpikeRule(config=config)
        matches = rule.evaluate(ctx)
        assert len(matches) == 1
