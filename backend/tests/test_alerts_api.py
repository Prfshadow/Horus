"""Tests for Alerts API (M3+M7.4)."""

from datetime import datetime, timedelta, timezone
from typing import Generator

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
def db_session() -> Generator[Session, None, None]:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
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
def client(db_session: Session) -> Generator[TestClient, None, None]:
    # Setup registry for lifespan file DB reset, but we override after
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


def insert_events(db, base, count, ip="10.0.0.1"):
    evs = []
    for i in range(count):
        e = Event(timestamp=base + timedelta(seconds=i), source="auth-service", level="ERROR", message="fail", raw_log="raw", extra_data={"ip": ip})
        db.add(e)
        evs.append(e)
    db.commit()
    for e in evs:
        db.refresh(e)
    return evs


def make_alert(db, ip="10.0.0.1", base=None, severity="HIGH", status="detected", rule_name="BruteForceLogin"):
    base = base or datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    ev = Event(timestamp=base, source="auth", level="ERROR", message="fail", raw_log="raw", extra_data={"ip": ip})
    db.add(ev)
    db.flush()
    alert = Alert(
        rule_id=1,
        rule_name=rule_name,
        status=status,
        severity=severity,
        detected_at=base,
        summary="test",
        context={"group_key": "extra_data.ip", "count": 1, "threshold": 5, "window_seconds": 60, "group_by": "extra_data.ip"},
        first_event_id=1,
        last_event_id=1,
    )
    db.add(alert)
    db.flush()
    ev = Event(timestamp=base, source="auth", level="ERROR", message="fail", raw_log="raw", extra_data={"ip": ip})
    db.add(ev)
    db.flush()
    db.add(AlertEvent(alert_id=alert.id, event_id=ev.id))
    db.commit()
    return alert


class TestAlertsAPI:
    def test_create_and_list_alerts(self, client, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        insert_events(db_session, base, 5, ip="1.1.1.1")
        eval_time = base + timedelta(seconds=60)
        # trigger detection
        resp = client.post("/api/v1/detect", json={"window_seconds": 60, "evaluation_time": eval_time.isoformat()})
        assert resp.status_code == 200
        assert resp.json()["alerts_created"] == 1
        # list - now returns paginated response
        resp2 = client.get("/api/v1/alerts")
        assert resp2.status_code == 200
        body = resp2.json()
        assert body["total"] == 1
        assert len(body["items"]) == 1
        assert body["items"][0]["rule_name"] == "BruteForceLogin"
        assert body["items"][0]["status"] == "detected"
        assert body["items"][0]["evidence_event_ids"] == sorted(body["items"][0]["evidence_event_ids"])

    def test_get_alert(self, client, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        insert_events(db_session, base, 5, ip="2.2.2.2")
        eval_time = base + timedelta(seconds=60)
        client.post("/api/v1/detect", json={"window_seconds": 60, "evaluation_time": eval_time.isoformat()})
        alerts = client.get("/api/v1/alerts").json()
        # Now returns paginated response
        aid = alerts["items"][0]["id"]
        resp = client.get(f"/api/v1/alerts/{aid}")
        assert resp.status_code == 200
        assert resp.json()["id"] == aid
        assert len(resp.json()["evidence_event_ids"]) == 5

    def test_update_alert_status(self, client, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        insert_events(db_session, base, 5, ip="3.3.3.3")
        eval_time = base + timedelta(seconds=60)
        client.post("/api/v1/detect", json={"window_seconds": 60, "evaluation_time": eval_time.isoformat()})
        alerts = client.get("/api/v1/alerts").json()
        aid = alerts["items"][0]["id"]
        # acknowledge
        resp = client.patch(f"/api/v1/alerts/{aid}", json={"status": "acknowledged"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "acknowledged"
        # resolve
        resp2 = client.patch(f"/api/v1/alerts/{aid}", json={"status": "resolved"})
        assert resp2.status_code == 200
        assert resp2.json()["status"] == "resolved"

    def test_alert_filters(self, client, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        insert_events(db_session, base, 5, ip="4.4.4.4")
        eval_time = base + timedelta(seconds=60)
        client.post("/api/v1/detect", json={"window_seconds": 60, "evaluation_time": eval_time.isoformat()})
        # filter by status
        resp = client.get("/api/v1/alerts?status=detected")
        assert len(resp.json()["items"]) == 1
        resp2 = client.get("/api/v1/alerts?status=resolved")
        assert len(resp2.json()["items"]) == 0
        # filter by rule
        resp3 = client.get("/api/v1/alerts?rule_name=BruteForceLogin")
        assert len(resp3.json()["items"]) == 1

    def test_get_nonexistent_alert(self, client):
        resp = client.get("/api/v1/alerts/9999")
        assert resp.status_code == 404