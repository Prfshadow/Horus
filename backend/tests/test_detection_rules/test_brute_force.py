"""Tests for BruteForceLoginRule (M3)."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import event as sa_event
from sqlalchemy.engine import Engine

from app.db.base import Base
from app.models.event import Event
from app.detection.rules.brute_force import BruteForceLoginRule
from app.detection.base import EvaluationContext


def make_event(id_: int, ts: datetime, ip: str, level: str = "ERROR", source: str = "auth-service") -> Event:
    # Create unsaved Event object with id set
    e = Event(
        timestamp=ts,
        source=source,
        level=level,
        message="failed login",
        raw_log="raw",
        extra_data={"ip": ip},
    )
    e.id = id_  # type: ignore
    return e


class TestBruteForceLoginRule:
    def setup_method(self):
        self.rule = BruteForceLoginRule()

    def test_exact_threshold_triggers(self):
        now = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        evs = [make_event(i, now - timedelta(seconds=10 + i), "10.0.0.5") for i in range(5)]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=60, rule_config=self.rule.default_config, db=None)  # type: ignore
        matches = self.rule.evaluate(ctx)
        assert len(matches) == 1
        assert matches[0].group_key == "10.0.0.5"
        assert matches[0].context["count"] == 5

    def test_below_threshold_no_alert(self):
        now = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        evs = [make_event(i, now - timedelta(seconds=i), "10.0.0.5") for i in range(4)]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=60, rule_config=self.rule.default_config, db=None)  # type: ignore
        matches = self.rule.evaluate(ctx)
        assert len(matches) == 0

    def test_window_lower_boundary_inclusive(self):
        now = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        cutoff = now - timedelta(seconds=60)
        # exactly at cutoff should be included
        evs = [make_event(i, cutoff, "10.0.0.5") for i in range(5)]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=60, rule_config=self.rule.default_config, db=None)  # type: ignore
        matches = self.rule.evaluate(ctx)
        assert len(matches) == 1

    def test_window_upper_boundary_inclusive(self):
        now = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        evs = [make_event(i, now, "10.0.0.5") for i in range(5)]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=60, rule_config=self.rule.default_config, db=None)  # type: ignore
        matches = self.rule.evaluate(ctx)
        assert len(matches) == 1

    def test_window_outside_excluded(self):
        now = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        # 1 second before cutoff should be excluded, leaving only 4 in window
        cutoff = now - timedelta(seconds=60)
        before = cutoff - timedelta(seconds=1)
        evs = [make_event(0, before, "10.0.0.5")] + [make_event(i + 1, now - timedelta(seconds=i), "10.0.0.5") for i in range(4)]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=60, rule_config=self.rule.default_config, db=None)  # type: ignore
        matches = self.rule.evaluate(ctx)
        assert len(matches) == 0

        # after evaluation_time excluded
        after = now + timedelta(seconds=1)
        evs2 = [make_event(i, now - timedelta(seconds=i), "10.0.0.5") for i in range(4)] + [make_event(99, after, "10.0.0.5")]
        ctx2 = EvaluationContext(window_events=evs2, evaluation_time=now, window_seconds=60, rule_config=self.rule.default_config, db=None)  # type: ignore
        matches2 = self.rule.evaluate(ctx2)
        assert len(matches2) == 0

    def test_multiple_ips(self):
        now = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        evs_a = [make_event(i, now - timedelta(seconds=i), "10.0.0.1") for i in range(5)]
        evs_b = [make_event(i + 10, now - timedelta(seconds=i), "10.0.0.2") for i in range(3)]
        ctx = EvaluationContext(window_events=evs_a + evs_b, evaluation_time=now, window_seconds=60, rule_config=self.rule.default_config, db=None)  # type: ignore
        matches = self.rule.evaluate(ctx)
        assert len(matches) == 1
        assert matches[0].group_key == "10.0.0.1"

    def test_filter_by_source_and_level(self):
        now = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        # 5 events but only 3 match filter (level ERROR)
        evs = [
            make_event(0, now, "10.0.0.5", level="ERROR"),
            make_event(1, now, "10.0.0.5", level="ERROR"),
            make_event(2, now, "10.0.0.5", level="ERROR"),
            make_event(3, now, "10.0.0.5", level="INFO"),
            make_event(4, now, "10.0.0.5", level="INFO"),
        ]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=60, rule_config=self.rule.default_config, db=None)  # type: ignore
        matches = self.rule.evaluate(ctx)
        assert len(matches) == 0

    def test_custom_threshold(self):
        now = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        config = {"threshold": 3, "window_seconds": 60, "group_by": "extra_data.ip", "filter": {"level": "ERROR"}}
        evs = [make_event(i, now, "10.0.0.5") for i in range(3)]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=60, rule_config=config, db=None)  # type: ignore
        matches = BruteForceLoginRule(config=config).evaluate(ctx)
        assert len(matches) == 1

    def _warn_auth_failure(self, id_: int, ts: datetime, ip: str, message: str = "Failed login attempt username=admin ip=10.10.5.44", level: str = "WARNING") -> Event:
        e = Event(
            timestamp=ts,
            source="auth.service",
            level=level,
            message=message,
            raw_log="raw",
            extra_data={"username": "admin", "ip": ip},
        )
        e.id = id_  # type: ignore
        return e

    def test_warning_auth_failures_trigger(self):
        # Real-world syslog shape: WARN "Failed login attempt ..." (the
        # stored DB filter only selects ERROR, the rule extends it in code).
        now = datetime(2026, 9, 24, 13, 43, 45, tzinfo=timezone.utc)
        evs = [self._warn_auth_failure(i, now - timedelta(seconds=9 - i), "10.10.5.44") for i in range(5)]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=60, rule_config=self.rule.default_config, db=None)  # type: ignore
        matches = self.rule.evaluate(ctx)
        assert len(matches) == 1
        assert matches[0].group_key == "10.10.5.44"
        assert matches[0].context["count"] == 5

    def test_warning_without_auth_signals_ignored(self):
        now = datetime(2026, 9, 24, 13, 43, 45, tzinfo=timezone.utc)
        evs = [
            self._warn_auth_failure(i, now - timedelta(seconds=i), "10.10.5.44", message="Failed to connect to database")
            for i in range(5)
        ]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=60, rule_config=self.rule.default_config, db=None)  # type: ignore
        assert self.rule.evaluate(ctx) == []

    def test_warning_blocked_connections_ignored(self):
        now = datetime(2026, 9, 24, 13, 43, 45, tzinfo=timezone.utc)
        evs = [
            self._warn_auth_failure(i, now - timedelta(seconds=i), "10.10.5.44", message="blocked 10.10.5.44 connection")
            for i in range(5)
        ]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=60, rule_config=self.rule.default_config, db=None)  # type: ignore
        assert self.rule.evaluate(ctx) == []

    def test_info_auth_failures_still_ignored(self):
        # Documented boundary: INFO never counts, even with auth keywords.
        now = datetime(2026, 9, 24, 13, 43, 45, tzinfo=timezone.utc)
        evs = [
            self._warn_auth_failure(i, now - timedelta(seconds=i), "10.10.5.44", level="INFO")
            for i in range(5)
        ]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=60, rule_config=self.rule.default_config, db=None)  # type: ignore
        assert self.rule.evaluate(ctx) == []

    def test_critical_auth_failures_trigger(self):
        now = datetime(2026, 9, 24, 13, 43, 45, tzinfo=timezone.utc)
        evs = [
            self._warn_auth_failure(i, now - timedelta(seconds=i), "10.10.5.44", level="CRITICAL", message="Failed password for root")
            for i in range(5)
        ]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=60, rule_config=self.rule.default_config, db=None)  # type: ignore
        matches = self.rule.evaluate(ctx)
        assert len(matches) == 1
        assert matches[0].context["count"] == 5

    def test_mixed_error_and_warning_count_together(self):
        now = datetime(2026, 9, 24, 13, 43, 45, tzinfo=timezone.utc)
        evs = [make_event(i, now - timedelta(seconds=i), "10.10.5.44") for i in range(3)]
        evs += [self._warn_auth_failure(10 + i, now - timedelta(seconds=i), "10.10.5.44") for i in range(2)]
        ctx = EvaluationContext(window_events=evs, evaluation_time=now, window_seconds=60, rule_config=self.rule.default_config, db=None)  # type: ignore
        matches = self.rule.evaluate(ctx)
        assert len(matches) == 1
        assert matches[0].context["count"] == 5
