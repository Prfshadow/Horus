"""Tests for Incidents API (M3+M7.4)."""

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
from app.models.alert import Alert
from app.models.alert_event import AlertEvent
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


class TestIncidentsAPI:
    def test_create_via_correlate_and_list(self, client, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        make_alert(db_session, "10.0.0.1", base)
        make_alert(db_session, "10.0.0.1", base + timedelta(seconds=10))
        client.post("/api/v1/correlate", json={"window_seconds": 3600, "evaluation_time": (base + timedelta(seconds=20)).isoformat(), "strategy": "source_ip"})
        resp = client.get("/api/v1/incidents")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert len(body["items"]) == 1
        assert body["items"][0]["context"]["strategy"] == "source_ip"
        assert body["items"][0]["status"] == "open"
        assert "alert_ids" in body["items"][0]
        assert len(body["items"][0]["alert_ids"]) > 0

    def test_get_incident(self, client, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        make_alert(db_session, "10.0.0.2", base)
        client.post("/api/v1/correlate", json={"window_seconds": 3600, "evaluation_time": (base + timedelta(seconds=10)).isoformat()})
        inc_id = client.get("/api/v1/incidents").json()["items"][0]["id"]
        resp = client.get(f"/api/v1/incidents/{inc_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == inc_id
        assert "alert_ids" in resp.json()
        assert len(resp.json()["alert_ids"]) > 0

    def test_patch_status_transitions(self, client, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        make_alert(db_session, "10.0.0.3", base)
        client.post("/api/v1/correlate", json={"window_seconds": 3600, "evaluation_time": (base + timedelta(seconds=10)).isoformat()})
        inc_id = client.get("/api/v1/incidents").json()["items"][0]["id"]
        # open -> investigating
        resp = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "investigating"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "investigating"
        # investigating -> resolved
        resp2 = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "resolved"})
        assert resp2.status_code == 200
        assert resp2.json()["status"] == "resolved"

    def test_invalid_transitions(self, client, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        make_alert(db_session, "10.0.0.4", base)
        client.post("/api/v1/correlate", json={"window_seconds": 3600, "evaluation_time": (base + timedelta(seconds=10)).isoformat()})
        inc_id = client.get("/api/v1/incidents").json()["items"][0]["id"]
        # open -> resolved invalid
        resp = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "resolved"})
        assert resp.status_code == 400
        # invalid status value
        resp2 = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "open"})
        assert resp2.status_code == 400
        # patch to investigating then back to open invalid
        client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "investigating"})
        resp3 = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "open"})
        assert resp3.status_code == 400

    def test_resolved_immutable(self, client, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        make_alert(db_session, "10.0.0.5", base)
        client.post("/api/v1/correlate", json={"window_seconds": 3600, "evaluation_time": (base + timedelta(seconds=10)).isoformat()})
        inc_id = client.get("/api/v1/incidents").json()["items"][0]["id"]
        client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "investigating"})
        client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "resolved"})
        resp = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "investigating"})
        assert resp.status_code == 400

    def test_404(self, client):
        resp = client.get("/api/v1/incidents/9999")
        assert resp.status_code == 404
        resp2 = client.patch("/api/v1/incidents/9999", json={"status": "investigating"})
        assert resp2.status_code == 404

    def test_filter(self, client, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        make_alert(db_session, "10.0.0.6", base)
        client.post("/api/v1/correlate", json={"window_seconds": 3600, "evaluation_time": (base + timedelta(seconds=10)).isoformat()})
        resp = client.get("/api/v1/incidents?status=open")
        assert len(resp.json()["items"]) == 1
        resp2 = client.get("/api/v1/incidents?status=resolved")
        assert len(resp2.json()["items"]) == 0