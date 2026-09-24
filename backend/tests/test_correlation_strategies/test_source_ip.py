"""Tests for SourceIpStrategy (M4)."""

from datetime import datetime, timezone, timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import event as sa_event

from app.db.base import Base
from app.models.event import Event
from app.models.alert import Alert
from app.models.alert_event import AlertEvent
from app.models.detection_rule import DetectionRule
from app.correlation.strategies.source_ip import SourceIpStrategy
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


def make_alert(db, rule_name, detected_at, group_key=None, ip_extra=None, severity="HIGH"):
    # Create event(s) for evidence if ip_extra provided
    context = {}
    if group_key is not None:
        context["group_key"] = group_key
        context["group_by"] = "extra_data.ip"
    alert = Alert(
        rule_id=1,
        rule_name=rule_name,
        status="detected",
        severity=severity,
        detected_at=detected_at,
        summary="test",
        context=context,
        first_event_id=1,
        last_event_id=1,
    )
    db.add(alert)
    db.flush()
    if ip_extra is not None:
        # ip_extra can be string or list of strings for ambiguous case
        ips = ip_extra if isinstance(ip_extra, list) else [ip_extra]
        for ip in ips:
            ev = Event(timestamp=detected_at, source="auth", level="ERROR", message="fail", raw_log="raw", extra_data={"ip": ip} if ip is not None else {})
            db.add(ev)
            db.flush()
            db.add(AlertEvent(alert_id=alert.id, event_id=ev.id))
            # update first/last
            alert.first_event_id = ev.id
            alert.last_event_id = ev.id
        db.flush()
    return alert


class TestSourceIpStrategy:
    def test_group_key_extraction(self, db):
        strat = SourceIpStrategy()
        alert = make_alert(db, "BruteForceLogin", datetime(2026,9,14,10,0,0,tzinfo=timezone.utc), group_key="10.0.0.5")
        db.commit()
        key = strat.extract_key(alert, db)
        assert key == "ip:10.0.0.5"

    def test_event_extra_ip_extraction(self, db):
        strat = SourceIpStrategy()
        alert = make_alert(db, "ErrorSpike", datetime(2026,9,14,10,0,0,tzinfo=timezone.utc), ip_extra="10.0.0.6")
        db.commit()
        key = strat.extract_key(alert, db)
        assert key == "ip:10.0.0.6"

    def test_missing_ip_skipped(self, db):
        strat = SourceIpStrategy()
        alert = make_alert(db, "ErrorSpike", datetime(2026,9,14,10,0,0,tzinfo=timezone.utc))
        db.commit()
        key = strat.extract_key(alert, db)
        assert key is None

    def test_conflicting_ip_skipped(self, db):
        strat = SourceIpStrategy()
        # Create alert with two events having different IPs
        ctx = {"group_key": None}
        alert = Alert(rule_id=1, rule_name="BruteForceLogin", status="detected", severity="HIGH", detected_at=datetime(2026,9,14,10,0,0,tzinfo=timezone.utc), summary="test", context={}, first_event_id=1, last_event_id=1)
        db.add(alert)
        db.flush()
        ev1 = Event(timestamp=alert.detected_at, source="auth", level="ERROR", message="fail", raw_log="raw", extra_data={"ip": "10.0.0.1"})
        ev2 = Event(timestamp=alert.detected_at, source="auth", level="ERROR", message="fail", raw_log="raw", extra_data={"ip": "10.0.0.2"})
        db.add(ev1)
        db.add(ev2)
        db.flush()
        db.add(AlertEvent(alert_id=alert.id, event_id=ev1.id))
        db.add(AlertEvent(alert_id=alert.id, event_id=ev2.id))
        db.commit()
        key = strat.extract_key(alert, db)
        assert key is None

    def test_grouping_same_ip(self, db):
        strat = SourceIpStrategy()
        a1 = make_alert(db, "BruteForceLogin", datetime(2026,9,14,10,0,0,tzinfo=timezone.utc), group_key="10.0.0.5")
        a2 = make_alert(db, "BruteForceLogin", datetime(2026,9,14,10,1,0,tzinfo=timezone.utc), group_key="10.0.0.5")
        a3 = make_alert(db, "BruteForceLogin", datetime(2026,9,14,10,2,0,tzinfo=timezone.utc), group_key="10.0.0.6")
        db.commit()
        groups = strat.group([a1,a2,a3], db)
        assert len(groups) == 2
        assert len(groups["ip:10.0.0.5"]) == 2
        assert len(groups["ip:10.0.0.6"]) == 1

    def test_group_key_priority_over_event(self, db):
        strat = SourceIpStrategy()
        # Alert has group_key 10.0.0.5 but event has 10.0.0.9 -> should use group_key
        alert = make_alert(db, "BruteForceLogin", datetime(2026,9,14,10,0,0,tzinfo=timezone.utc), group_key="10.0.0.5", ip_extra="10.0.0.9")
        db.commit()
        key = strat.extract_key(alert, db)
        assert key == "ip:10.0.0.5"
