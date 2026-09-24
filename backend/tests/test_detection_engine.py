"""Tests for DetectionEngine (M3)."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import event as sa_event

from app.db.base import Base
from app.models.event import Event
from app.models.detection_rule import DetectionRule
from app.detection.engine import DetectionEngine
from app.detection.registry import rule_registry
from app.detection.rules.brute_force import BruteForceLoginRule
from app.detection.rules.error_spike import ErrorSpikeRule
from app.services.detection import ensure_default_rules


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    @sa_event.listens_for(engine, "connect")
    def fk_on(dbapi_conn, conn_rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    session = TestingSession()
    ensure_default_rules(session)
    # Setup registry
    rule_registry.clear_all()
    rule_registry.register_class("threshold", BruteForceLoginRule)
    rule_registry.register_class("frequency", ErrorSpikeRule)
    for rm in session.execute(select(DetectionRule)).scalars().all():
        cls = rule_registry.get_class(rm.rule_type)
        if cls:
            inst = cls(config=rm.config)
            inst.name = rm.name
            rule_registry.register_instance(rm.name, inst)
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
        rule_registry.clear_all()


def insert_events(db: Session, events_data: list[dict]) -> list[Event]:
    evs = []
    for d in events_data:
        e = Event(**d)
        db.add(e)
        evs.append(e)
    db.commit()
    for e in evs:
        db.refresh(e)
    return evs


class TestDetectionEngine:
    def test_scan_recent_brute_force(self, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        eval_time = base + timedelta(seconds=60)
        # 5 events from same IP within window
        data = [
            {"timestamp": base + timedelta(seconds=i), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.5"}}
            for i in range(5)
        ]
        insert_events(db_session, data)
        engine = DetectionEngine()
        results = engine.scan_recent(db=db_session, window_seconds=60, evaluation_time=eval_time)
        # Should have 1 match for BruteForceLogin
        brute = [r for r in results if r["rule_model"].name == "BruteForceLogin"]
        assert len(brute) == 1
        assert brute[0]["match"].group_key == "10.0.0.5"

    def test_scan_recent_evaluation_time_deterministic(self, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        # Event at 10:00:50
        data = [
            {"timestamp": base + timedelta(seconds=50), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "1.1.1.1"}}
            for _ in range(5)
        ]
        insert_events(db_session, data)
        engine = DetectionEngine()
        # eval at 10:01:00 -> within 60s window includes events
        eval1 = base + timedelta(seconds=60)
        results1 = engine.scan_recent(db=db_session, window_seconds=60, evaluation_time=eval1)
        assert len([r for r in results1 if r["rule_model"].name == "BruteForceLogin"]) == 1
        # eval at 10:02:00 -> outside window, no match
        eval2 = base + timedelta(seconds=120)
        results2 = engine.scan_recent(db=db_session, window_seconds=60, evaluation_time=eval2)
        assert len([r for r in results2 if r["rule_model"].name == "BruteForceLogin"]) == 0

    def test_scan_recent_rule_filter(self, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        eval_time = base + timedelta(seconds=60)
        data = [
            {"timestamp": base + timedelta(seconds=i), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.5"}}
            for i in range(5)
        ]
        insert_events(db_session, data)
        engine = DetectionEngine()
        # Only ErrorSpike -> should be 0 because ErrorSpike needs min 10
        results = engine.scan_recent(db=db_session, window_seconds=60, evaluation_time=eval_time, rule_names=["ErrorSpike"])
        assert len([r for r in results if r["rule_model"].name == "BruteForceLogin"]) == 0

    def test_scan_recent_boundary_inclusive(self, db_session):
        """Events exactly at evaluation_time - window_seconds should be included."""
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        # Event exactly at cutoff (eval_time - window_seconds)
        eval_time = base + timedelta(seconds=60)
        data = [
            {"timestamp": base, "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.1"}},
            {"timestamp": base + timedelta(seconds=10), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.1"}},
            {"timestamp": base + timedelta(seconds=20), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.1"}},
            {"timestamp": base + timedelta(seconds=30), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.1"}},
            {"timestamp": base + timedelta(seconds=40), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.1"}},
        ]
        insert_events(db_session, data)
        engine = DetectionEngine()
        results = engine.scan_recent(db=db_session, window_seconds=60, evaluation_time=eval_time)
        brute = [r for r in results if r["rule_model"].name == "BruteForceLogin"]
        assert len(brute) == 1, "Event at exact boundary should be included"

    def test_scan_recent_boundary_exclusive_before(self, db_session):
        """Event just before evaluation_time - window_seconds should be excluded."""
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        eval_time = base + timedelta(seconds=60)
        # Event 1 second before cutoff (at 10:00:00, cutoff is 10:00:00 for 60s window ending at 10:01:00)
        data = [
            {"timestamp": base - timedelta(seconds=1), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.1"}},
            {"timestamp": base + timedelta(seconds=10), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.1"}},
            {"timestamp": base + timedelta(seconds=20), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.1"}},
            {"timestamp": base + timedelta(seconds=30), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.1"}},
            {"timestamp": base + timedelta(seconds=40), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.1"}},
        ]
        insert_events(db_session, data)
        engine = DetectionEngine()
        results = engine.scan_recent(db=db_session, window_seconds=60, evaluation_time=eval_time)
        brute = [r for r in results if r["rule_model"].name == "BruteForceLogin"]
        assert len(brute) == 0, "Event just before boundary should be excluded"

    def test_scan_recent_future_events_excluded(self, db_session):
        """Events after evaluation_time should NOT be considered."""
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        eval_time = base + timedelta(seconds=60)
        # 5 events in window, plus 5 future events
        data = [
            {"timestamp": base + timedelta(seconds=i), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.1"}}
            for i in range(5)
        ] + [
            {"timestamp": eval_time + timedelta(seconds=i * 10), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.1"}}
            for i in range(5)
        ]
        insert_events(db_session, data)
        engine = DetectionEngine()
        results = engine.scan_recent(db=db_session, window_seconds=60, evaluation_time=eval_time)
        brute = [r for r in results if r["rule_model"].name == "BruteForceLogin"]
        assert len(brute) == 1, "Future events should not be counted"

    def test_scan_recent_synthetic_flag_no_effect(self, db_session):
        """Synthetic flag in extra_data should not affect detection."""
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        eval_time = base + timedelta(seconds=60)
        # 5 synthetic events
        synthetic_data = [
            {"timestamp": base + timedelta(seconds=i), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.1", "synthetic": True}}
            for i in range(5)
        ]
        # 5 non-synthetic events (different IP)
        normal_data = [
            {"timestamp": base + timedelta(seconds=i), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.2"}}
            for i in range(5)
        ]
        insert_events(db_session, synthetic_data + normal_data)
        engine = DetectionEngine()
        results = engine.scan_recent(db=db_session, window_seconds=60, evaluation_time=eval_time)
        brute = [r for r in results if r["rule_model"].name == "BruteForceLogin"]
        assert len(brute) == 2, "Synthetic and non-synthetic should be treated equally"
        # Both IPs should have matches
        group_keys = {m["match"].group_key for m in brute}
        assert group_keys == {"10.0.0.1", "10.0.0.2"}
