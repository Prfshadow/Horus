"""Tests for Correlation API (M4)."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
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
    try:
        yield s
    finally:
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


def make_alert(db, ip, detected_at, host=None, rule_name="BruteForceLogin"):
    context = {"group_key": ip, "group_by": "extra_data.ip"} if ip else {}
    alert = Alert(rule_id=1, rule_name=rule_name, status="detected", severity="HIGH", detected_at=detected_at, summary="test", context=context, first_event_id=1, last_event_id=1)
    db.add(alert)
    db.flush()
    ev = Event(timestamp=detected_at, source="auth", level="ERROR", host=host, message="fail", raw_log="raw", extra_data={"ip": ip} if ip else {"host": host} if host else {})
    # For host test, ensure extra_data host if needed
    if host and not ev.host:
        ev.extra_data = {"host": host}
    db.add(ev)
    db.flush()
    db.add(AlertEvent(alert_id=alert.id, event_id=ev.id))
    alert.first_event_id = ev.id
    alert.last_event_id = ev.id
    db.commit()
    return alert


class TestCorrelationAPI:
    def test_default_strategy_source_ip(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        make_alert(db_session, "10.0.0.1", base)
        make_alert(db_session, "10.0.0.1", base+timedelta(seconds=10))
        resp = client.post("/api/v1/correlate", json={"window_seconds":3600, "evaluation_time": (base+timedelta(seconds=20)).isoformat()})
        assert resp.status_code == 200
        assert resp.json()["strategy"] == "source_ip"
        assert resp.json()["incidents_created"] == 1

    def test_host_strategy(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        # Create alerts with host
        a1 = make_alert(db_session, None, base, host="server-01")
        # Need to adjust a1 to have host strategy key
        # For host, context not needed, event host is used
        a2 = make_alert(db_session, None, base+timedelta(seconds=10), host="server-01")
        resp = client.post("/api/v1/correlate", json={"window_seconds":3600, "evaluation_time": (base+timedelta(seconds=20)).isoformat(), "strategy":"host"})
        assert resp.status_code == 200
        assert resp.json()["strategy"] == "host"
        assert resp.json()["incidents_created"] == 1

    def test_rule_names_filter(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        make_alert(db_session, "10.0.0.2", base, rule_name="BruteForceLogin")
        make_alert(db_session, "10.0.0.2", base+timedelta(seconds=10), rule_name="ErrorSpike")
        resp = client.post("/api/v1/correlate", json={"window_seconds":3600, "evaluation_time": (base+timedelta(seconds=20)).isoformat(), "rule_names":["BruteForceLogin"]})
        assert resp.status_code == 200
        assert resp.json()["alerts_correlated"] == 1

    def test_future_excluded(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        make_alert(db_session, "10.0.0.3", base+timedelta(seconds=100))
        resp = client.post("/api/v1/correlate", json={"window_seconds":3600, "evaluation_time": base.isoformat()})
        assert resp.json()["alerts_correlated"] == 0

    def test_validation(self, client):
        resp = client.post("/api/v1/correlate", json={"strategy":"invalid"})
        assert resp.status_code == 422
        resp2 = client.post("/api/v1/correlate", json={"window_seconds":0})
        assert resp2.status_code == 422

    def test_idempotent_second_run(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        make_alert(db_session, "10.0.0.4", base)
        make_alert(db_session, "10.0.0.4", base+timedelta(seconds=10))
        resp1 = client.post("/api/v1/correlate", json={"window_seconds":3600, "evaluation_time": (base+timedelta(seconds=20)).isoformat()})
        assert resp1.json()["incidents_created"] == 1
        resp2 = client.post("/api/v1/correlate", json={"window_seconds":3600, "evaluation_time": (base+timedelta(seconds=20)).isoformat()})
        assert resp2.json()["incidents_created"] == 0
        assert resp2.json()["alerts_correlated"] == 0
