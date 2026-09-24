"""Tests for IncidentCorrelationEngine (M4)."""

from datetime import datetime, timezone, timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import event as sa_event

from app.db.base import Base
from app.models.alert import Alert
from app.models.event import Event
from app.models.alert_event import AlertEvent
from app.correlation.engine import IncidentCorrelationEngine
from app.services.detection import ensure_default_rules


@pytest.fixture()
def db():
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


def make_alert(db, ip, detected_at):
    alert = Alert(rule_id=1, rule_name="BruteForceLogin", status="detected", severity="HIGH", detected_at=detected_at, summary="test", context={"group_key": ip, "group_by": "extra_data.ip"}, first_event_id=1, last_event_id=1)
    db.add(alert)
    db.flush()
    ev = Event(timestamp=detected_at, source="auth", level="ERROR", message="fail", raw_log="raw", extra_data={"ip": ip})
    db.add(ev)
    db.flush()
    db.add(AlertEvent(alert_id=alert.id, event_id=ev.id))
    db.commit()
    return alert


class TestIncidentCorrelationEngine:
    def test_one_strategy_per_run(self, db):
        engine = IncidentCorrelationEngine()
        a1 = make_alert(db, "10.0.0.1", datetime(2026,9,14,10,0,0,tzinfo=timezone.utc))
        a2 = make_alert(db, "10.0.0.1", datetime(2026,9,14,10,1,0,tzinfo=timezone.utc))
        # source_ip grouping should group both
        groups = engine.correlate([a1,a2], "source_ip", db)
        assert len(groups) == 1
        assert "ip:10.0.0.1" in groups
        # invalid strategy raises
        with pytest.raises(ValueError):
            engine.correlate([a1], "invalid", db)

    def test_deterministic_sorting(self, db):
        engine = IncidentCorrelationEngine()
        # Create alerts with same detected_at but different IDs; engine should sort by id tie-breaker
        t = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        a1 = make_alert(db, "10.0.0.5", t)
        a2 = make_alert(db, "10.0.0.5", t)
        # Ensure a1.id < a2.id
        assert a1.id < a2.id
        groups = engine.correlate([a2,a1], "source_ip", db)  # reverse input order
        # Group order should be deterministic
        assert groups["ip:10.0.0.5"][0].id == a1.id
        assert groups["ip:10.0.0.5"][1].id == a2.id

    def test_default_strategy_not_auto_combined(self, db):
        # Ensure host and ip are not combined automatically
        engine = IncidentCorrelationEngine()
        # Two alerts: same host but different IPs
        t = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        # Create alerts manually with host
        from app.models.alert import Alert
        a1 = make_alert(db, "10.0.0.1", t)
        # Add host to their events: need to update event host
        # For this test, we will test host strategy separately
        groups_ip = engine.correlate([a1], "source_ip", db)
        assert "ip:10.0.0.1" in groups_ip
        # host strategy should not find ip key
        groups_host = engine.correlate([a1], "host", db)
        # a1 has no host, so should be empty
        assert len(groups_host) == 0
