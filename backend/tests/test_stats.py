from datetime import datetime, timezone, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import event as sa_event

from fastapi.testclient import TestClient
from app.main import create_app
from app.db.base import Base
from app.db.session import get_db
from app.models.event import Event
from app.models.alert import Alert
from app.models.incident import Incident
from app.services.detection import ensure_default_rules
from sqlalchemy import select
from app.models.detection_rule import DetectionRule
from app.detection.registry import rule_registry
from app.detection.rules.brute_force import BruteForceLoginRule
from app.detection.rules.error_spike import ErrorSpikeRule

import pytest
from sqlalchemy.orm import Session

@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    @sa_event.listens_for(engine, "connect")
    def fk_on(dbapi_conn, conn_rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    s = Session()
    ensure_default_rules(s)
    yield s
    s.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()

@pytest.fixture()
def client(db_session):
    app = create_app()
    def override():
        yield db_session
    app.dependency_overrides[get_db] = override
    with TestClient(app) as c:
        # setup registry for detection rules
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

def test_stats_empty(client):
    resp = client.get("/api/v1/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["events"]["total"] == 0
    assert data["alerts"]["total"] == 0
    assert data["alerts"]["active"] == 0
    assert data["alerts"]["by_severity"] == {}
    assert data["incidents"]["open"] == 0
    assert "generated_at" in data

def test_stats_populated(client, db_session):
    base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    # 2 events
    for i in range(2):
        ev = Event(timestamp=base + timedelta(seconds=i), source="auth", level="ERROR", message="fail", raw_log="raw")
        db_session.add(ev)
    # 2 alerts: one detected HIGH, one acknowledged MEDIUM
    ev = db_session.query(Event).first()
    alert1 = Alert(rule_id=1, rule_name="BruteForceLogin", status="detected", severity="HIGH", detected_at=base, summary="test", context={}, first_event_id=ev.id if ev else 1, last_event_id=ev.id if ev else 1)
    alert2 = Alert(rule_id=1, rule_name="BruteForceLogin", status="acknowledged", severity="MEDIUM", detected_at=base, summary="test", context={}, first_event_id=1, last_event_id=1)
    db_session.add(alert1)
    db_session.add(alert2)
    # 3 incidents: 1 open HIGH, 1 investigating MEDIUM, 1 resolved LOW
    inc1 = Incident(title="t", status="open", severity="HIGH", correlation_key="ip:1", context={"strategy":"source_ip","correlation_key":"ip:1","correlation_window_seconds":3600}, first_seen_at=base, last_seen_at=base)
    inc2 = Incident(title="t", status="investigating", severity="MEDIUM", correlation_key="ip:2", context={"strategy":"source_ip","correlation_key":"ip:2","correlation_window_seconds":3600}, first_seen_at=base, last_seen_at=base)
    inc3 = Incident(title="t", status="resolved", severity="LOW", correlation_key="ip:3", context={"strategy":"source_ip","correlation_key":"ip:3","correlation_window_seconds":3600}, first_seen_at=base, last_seen_at=base)
    db_session.add_all([inc1, inc2, inc3])
    db_session.commit()

    resp = client.get("/api/v1/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["events"]["total"] == 2
    assert data["alerts"]["total"] == 2
    assert data["alerts"]["active"] == 2
    assert data["alerts"]["by_severity"]["HIGH"] == 1
    assert data["alerts"]["by_severity"]["MEDIUM"] == 1
    assert data["alerts"]["by_status"]["detected"] == 1
    assert data["incidents"]["open"] == 1
    assert data["incidents"]["investigating"] == 1
    assert data["incidents"]["resolved"] == 1
    assert data["incidents"]["by_severity"]["HIGH"] == 1

def test_stats_resolved_not_active(client, db_session):
    base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    alert = Alert(rule_id=1, rule_name="BruteForceLogin", status="resolved", severity="LOW", detected_at=base, summary="test", context={}, first_event_id=1, last_event_id=1)
    db_session.add(alert)
    db_session.commit()
    resp = client.get("/api/v1/stats")
    assert resp.json()["alerts"]["active"] == 0
    assert resp.json()["alerts"]["by_status"]["resolved"] == 1
