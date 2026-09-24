"""Tests for HostStrategy (M4)."""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import event as sa_event

from app.db.base import Base
from app.models.event import Event
from app.models.alert import Alert
from app.models.alert_event import AlertEvent
from app.correlation.strategies.host import HostStrategy
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


def make_alert_with_host(db, host=None, extra_host=None, detected_at=None):
    if detected_at is None:
        detected_at = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
    alert = Alert(rule_id=1, rule_name="ErrorSpike", status="detected", severity="MEDIUM", detected_at=detected_at, summary="test", context={}, first_event_id=1, last_event_id=1)
    db.add(alert)
    db.flush()
    ev = Event(timestamp=detected_at, source="app", level="ERROR", host=host, message="err", raw_log="raw", extra_data={"host": extra_host} if extra_host else {})
    # If host is set but extra_host also, host takes priority; extra_data host should not be considered if host exists
    if host and extra_host:
        ev.extra_data = {"host": extra_host}
    db.add(ev)
    db.flush()
    db.add(AlertEvent(alert_id=alert.id, event_id=ev.id))
    db.commit()
    return alert


class TestHostStrategy:
    def test_host_from_event_host(self, db):
        strat = HostStrategy()
        alert = make_alert_with_host(db, host="server-01")
        key = strat.extract_key(alert, db)
        assert key == "host:server-01"

    def test_extra_host_fallback(self, db):
        strat = HostStrategy()
        alert = make_alert_with_host(db, host=None, extra_host="server-02")
        key = strat.extract_key(alert, db)
        assert key == "host:server-02"

    def test_host_priority(self, db):
        strat = HostStrategy()
        alert = make_alert_with_host(db, host="server-01", extra_host="server-02")
        key = strat.extract_key(alert, db)
        assert key == "host:server-01"

    def test_missing_host_skipped(self, db):
        strat = HostStrategy()
        alert = make_alert_with_host(db, host=None, extra_host=None)
        key = strat.extract_key(alert, db)
        assert key is None

    def test_conflicting_hosts_skipped(self, db):
        strat = HostStrategy()
        alert = Alert(rule_id=1, rule_name="ErrorSpike", status="detected", severity="MEDIUM", detected_at=datetime(2026,9,14,10,0,0,tzinfo=timezone.utc), summary="test", context={}, first_event_id=1, last_event_id=1)
        db.add(alert)
        db.flush()
        ev1 = Event(timestamp=alert.detected_at, source="app", level="ERROR", host="server-01", message="err", raw_log="raw", extra_data={})
        ev2 = Event(timestamp=alert.detected_at, source="app", level="ERROR", host="server-02", message="err", raw_log="raw", extra_data={})
        db.add(ev1)
        db.add(ev2)
        db.flush()
        db.add(AlertEvent(alert_id=alert.id, event_id=ev1.id))
        db.add(AlertEvent(alert_id=alert.id, event_id=ev2.id))
        db.commit()
        key = strat.extract_key(alert, db)
        assert key is None

    def test_grouping_same_host(self, db):
        strat = HostStrategy()
        a1 = make_alert_with_host(db, host="server-01", detected_at=datetime(2026,9,14,10,0,0,tzinfo=timezone.utc))
        a2 = make_alert_with_host(db, host="server-01", detected_at=datetime(2026,9,14,10,1,0,tzinfo=timezone.utc))
        a3 = make_alert_with_host(db, host="server-02", detected_at=datetime(2026,9,14,10,2,0,tzinfo=timezone.utc))
        groups = strat.group([a1,a2,a3], db)
        assert len(groups) == 2
        assert len(groups["host:server-01"]) == 2
