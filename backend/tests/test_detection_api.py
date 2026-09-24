"""Tests for Detection API (M3)."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import event as sa_event

from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.event import Event
from app.models.detection_rule import DetectionRule
from app.services.detection import ensure_default_rules
from app.detection.registry import rule_registry
from app.detection.rules.brute_force import BruteForceLoginRule
from app.detection.rules.error_spike import ErrorSpikeRule


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
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture()
def client(db_session):
    app = create_app()
    def override_get_db():
        yield db_session
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        rule_registry.clear_all()
        rule_registry.register_class("threshold", BruteForceLoginRule)
        rule_registry.register_class("frequency", ErrorSpikeRule)
        for rm in db_session.execute(select(DetectionRule)).scalars().all():
            cls = rule_registry.get_class(rm.rule_type)
            if cls:
                inst = cls(config=rm.config)
                inst.name = rm.name
                rule_registry.register_instance(rm.name, inst)
        yield c
    app.dependency_overrides.clear()
    rule_registry.clear_all()


class TestDetectionAPI:
    def test_detect_brute_force(self, client, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(5):
            e = Event(timestamp=base + timedelta(seconds=i), source="auth-service", level="ERROR", message="fail", raw_log="raw", extra_data={"ip": "5.5.5.5"})
            db_session.add(e)
        db_session.commit()
        eval_time = base + timedelta(seconds=60)
        resp = client.post("/api/v1/detect", json={"window_seconds": 60, "evaluation_time": eval_time.isoformat()})
        assert resp.status_code == 200
        body = resp.json()
        assert body["window_seconds"] == 60
        assert body["alerts_created"] == 1
        assert len(body["alerts"]) == 1
        assert body["alerts"][0]["rule_name"] == "BruteForceLogin"

    def test_detect_with_rule_filter(self, client, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(5):
            e = Event(timestamp=base + timedelta(seconds=i), source="auth-service", level="ERROR", message="fail", raw_log="raw", extra_data={"ip": "6.6.6.6"})
            db_session.add(e)
        db_session.commit()
        eval_time = base + timedelta(seconds=60)
        # Only ErrorSpike, which should not fire for 5 events
        resp = client.post("/api/v1/detect", json={"window_seconds": 60, "evaluation_time": eval_time.isoformat(), "rule_names": ["ErrorSpike"]})
        assert resp.status_code == 200
        assert resp.json()["alerts_created"] == 0

    def test_detect_no_events(self, client):
        resp = client.post("/api/v1/detect", json={"window_seconds": 60})
        assert resp.status_code == 200
        assert resp.json()["alerts_created"] == 0

    def test_detect_error_spike(self, client, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        # Need min 10 and rate 20/min in 60s window: 20 events in 60s => 20/min
        # Use custom rule? Default ErrorSpike needs 10 in 300s with 20/min: 10/5min=2/min not enough.
        # Create a service spike with lower window for test: use brute? easier to test error spike via direct service
        # Let's trigger error spike by inserting many ERROR events for same service quickly
        # Default ErrorSpike: min 10, window 300, rate 20/min => need 100 events in 300s to get 20/min. Instead we test via smaller window override
        # For this test, update rule config
        from sqlalchemy import select
        rule = db_session.execute(select(DetectionRule).where(DetectionRule.name == "ErrorSpike")).scalars().first()
        rule.config = {"min_events": 5, "window_seconds": 60, "rate_threshold": 5, "group_by": "service", "filter": {"level": "ERROR"}}
        db_session.commit()
        # re-register
        rule_registry.clear_all()
        rule_registry.register_class("threshold", BruteForceLoginRule)
        rule_registry.register_class("frequency", ErrorSpikeRule)
        for rm in db_session.execute(select(DetectionRule)).scalars().all():
            cls = rule_registry.get_class(rm.rule_type)
            if cls:
                inst = cls(config=rm.config)
                inst.name = rm.name
                rule_registry.register_instance(rm.name, inst)

        for i in range(6):
            e = Event(timestamp=base + timedelta(seconds=i * 5), source="app", level="ERROR", service="payments", message="err", raw_log="raw", extra_data={})
            db_session.add(e)
        db_session.commit()
        eval_time = base + timedelta(seconds=60)
        resp = client.post("/api/v1/detect", json={"window_seconds": 60, "evaluation_time": eval_time.isoformat(), "rule_names": ["ErrorSpike"]})
        assert resp.status_code == 200
        assert resp.json()["alerts_created"] == 1
        assert resp.json()["alerts"][0]["context"]["group_key"] == "payments"

    def test_detect_no_evaluation_time_uses_current_time(self, client, db_session):
        """Default behavior without evaluation_time should work (uses server time)."""
        # Use a base time very close to now so events fall in the 60s window
        base = datetime.now(timezone.utc) - timedelta(seconds=30)
        for i in range(5):
            e = Event(timestamp=base + timedelta(seconds=i), source="auth-service", level="ERROR", message="fail", raw_log="raw", extra_data={"ip": "7.7.7.7"})
            db_session.add(e)
        db_session.commit()
        resp = client.post("/api/v1/detect", json={"window_seconds": 60})
        assert resp.status_code == 200
        body = resp.json()
        assert "evaluation_time" in body
        assert body["alerts_created"] == 1

    def test_detect_explicit_evaluation_time_response(self, client, db_session):
        """Response evaluation_time should match normalized UTC value."""
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(5):
            e = Event(timestamp=base + timedelta(seconds=i), source="auth-service", level="ERROR", message="fail", raw_log="raw", extra_data={"ip": "8.8.8.8"})
            db_session.add(e)
        db_session.commit()
        eval_time = base + timedelta(seconds=60)
        resp = client.post("/api/v1/detect", json={"window_seconds": 60, "evaluation_time": eval_time.isoformat()})
        assert resp.status_code == 200
        body = resp.json()
        # Response evaluation_time should be normalized to UTC
        assert body["evaluation_time"].endswith("Z") or "+00:00" in body["evaluation_time"]
        assert body["alerts_created"] == 1

    def test_detect_invalid_evaluation_time_rejected(self, client):
        """Non-timezone-aware evaluation_time should be rejected."""
        resp = client.post("/api/v1/detect", json={"window_seconds": 60, "evaluation_time": "2026-09-22T10:00:00"})  # no timezone
        assert resp.status_code == 422, "Should reject naive datetime"

    def test_detect_evaluation_time_future_events_excluded(self, client, db_session):
        """Events after evaluation_time should not be detected."""
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        eval_time = base + timedelta(seconds=60)
        # Events in window
        for i in range(5):
            e = Event(timestamp=base + timedelta(seconds=i), source="auth-service", level="ERROR", message="fail", raw_log="raw", extra_data={"ip": "9.9.9.9"})
            db_session.add(e)
        # Future events (after eval_time)
        for i in range(5):
            e = Event(timestamp=eval_time + timedelta(seconds=i * 10), source="auth-service", level="ERROR", message="fail", raw_log="raw", extra_data={"ip": "9.9.9.9"})
            db_session.add(e)
        db_session.commit()
        resp = client.post("/api/v1/detect", json={"window_seconds": 60, "evaluation_time": eval_time.isoformat()})
        assert resp.status_code == 200
        assert resp.json()["alerts_created"] == 1

    def test_detect_synthetic_flag_no_effect(self, client, db_session):
        """Synthetic flag should not bypass detection."""
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        eval_time = base + timedelta(seconds=60)
        # Synthetic events
        for i in range(5):
            e = Event(timestamp=base + timedelta(seconds=i), source="auth-service", level="ERROR", message="fail", raw_log="raw", extra_data={"ip": "10.10.10.1", "synthetic": True})
            db_session.add(e)
        # Non-synthetic events
        for i in range(5):
            e = Event(timestamp=base + timedelta(seconds=i), source="auth-service", level="ERROR", message="fail", raw_log="raw", extra_data={"ip": "10.10.10.2"})
            db_session.add(e)
        db_session.commit()
        resp = client.post("/api/v1/detect", json={"window_seconds": 60, "evaluation_time": eval_time.isoformat()})
        assert resp.status_code == 200
        body = resp.json()
        assert body["alerts_created"] == 2, "Synthetic and non-synthetic treated equally"
