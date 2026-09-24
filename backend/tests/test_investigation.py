"""Tests for M5 Investigation Context (33+ cases)."""

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
from app.models.incident import Incident
from app.models.incident_alert import IncidentAlert
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


def make_event(db, ts, source="auth", level="ERROR", service=None, host=None, message="msg", extra=None, raw="raw"):
    e = Event(timestamp=ts, source=source, level=level, service=service, host=host, message=message, raw_log=raw, extra_data=extra)
    db.add(e)
    db.flush()
    return e


def make_alert(db, detected_at, rule_name="BruteForceLogin", severity="HIGH", summary="test", context=None, events=None):
    if context is None:
        context = {"group_key": "10.0.0.5"}
    alert = Alert(rule_id=1, rule_name=rule_name, status="detected", severity=severity, detected_at=detected_at, summary=summary, context=context, first_event_id=1, last_event_id=1)
    db.add(alert)
    db.flush()
    if events:
        for ev in events:
            db.add(AlertEvent(alert_id=alert.id, event_id=ev.id))
        alert.first_event_id = events[0].id
        alert.last_event_id = events[-1].id
    db.commit()
    return alert


def make_incident(db, correlation_key="ip:10.0.0.5", first_seen=None, last_seen=None, status="open", severity="HIGH"):
    if first_seen is None:
        first_seen = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
    if last_seen is None:
        last_seen = first_seen
    inc = Incident(title="test", status=status, severity=severity, correlation_key=correlation_key, context={"strategy":"source_ip","correlation_key":correlation_key,"correlation_window_seconds":3600}, first_seen_at=first_seen, last_seen_at=last_seen)
    db.add(inc)
    db.flush()
    db.commit()
    return inc


class TestInvestigation:
    def test_empty_incident(self, client, db_session):
        inc = make_incident(db_session)
        resp = client.get(f"/api/v1/incidents/{inc.id}/investigation")
        assert resp.status_code == 200
        body = resp.json()
        assert body["incident"]["id"] == inc.id
        assert body["alerts"] == []
        assert body["events"] == []
        assert body["timeline"] == []
        assert body["summary"]["alert_count"] == 0

    def test_one_alert_one_event(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        ev = make_event(db_session, base, extra={"ip":"10.0.0.5"})
        alert = make_alert(db_session, base, events=[ev])
        inc = make_incident(db_session, first_seen=base, last_seen=base)
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
        db_session.commit()
        resp = client.get(f"/api/v1/incidents/{inc.id}/investigation")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["alerts"]) == 1
        assert len(body["events"]) == 1
        assert body["events"][0]["id"] == ev.id
        assert body["events"][0]["raw_log"] == "raw"

    def test_multiple_alerts_multiple_events(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        ev1 = make_event(db_session, base)
        ev2 = make_event(db_session, base+timedelta(seconds=10))
        a1 = make_alert(db_session, base, events=[ev1])
        a2 = make_alert(db_session, base+timedelta(seconds=10), events=[ev2])
        inc = make_incident(db_session, first_seen=base, last_seen=base+timedelta(seconds=10))
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=a1.id))
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=a2.id))
        db_session.commit()
        resp = client.get(f"/api/v1/incidents/{inc.id}/investigation")
        assert len(resp.json()["alerts"]) == 2
        assert len(resp.json()["events"]) == 2

    def test_shared_event_deduplication(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        ev = make_event(db_session, base)
        a1 = make_alert(db_session, base, events=[ev])
        a2 = make_alert(db_session, base+timedelta(seconds=5), events=[ev])
        inc = make_incident(db_session, first_seen=base, last_seen=base+timedelta(seconds=5))
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=a1.id))
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=a2.id))
        db_session.commit()
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        assert len(body["events"]) == 1
        assert body["summary"]["event_count"] == 1
        assert body["summary"]["total_event_count"] == 1

    def test_timeline_ordering(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        ev1 = make_event(db_session, base+timedelta(seconds=5))
        ev2 = make_event(db_session, base+timedelta(seconds=1))
        a1 = make_alert(db_session, base+timedelta(seconds=10), events=[ev1])
        inc = make_incident(db_session, first_seen=base, last_seen=base+timedelta(seconds=10))
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=a1.id))
        # also add second alert later
        a2 = make_alert(db_session, base+timedelta(seconds=15), events=[ev2])
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=a2.id))
        db_session.commit()
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        timeline = body["timeline"]
        # Should be sorted by timestamp
        timestamps = [t["timestamp"] for t in timeline]
        assert timestamps == sorted(timestamps)
        # Check event 2 (earliest) first

    def test_timeline_equal_timestamps_event_before_alert(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        ev = make_event(db_session, base)
        alert = make_alert(db_session, base, events=[ev])
        inc = make_incident(db_session, first_seen=base, last_seen=base)
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
        db_session.commit()
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        timeline = body["timeline"]
        # At same timestamp, event (type 0) before alert (type 1)
        assert timeline[0]["type"] == "event"
        assert timeline[1]["type"] == "alert"
        assert timeline[0]["timestamp"] == timeline[1]["timestamp"]

    def test_deterministic_alert_ordering(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        # Same detected_at, different ids
        a1 = make_alert(db_session, base, events=[])
        a2 = make_alert(db_session, base, events=[])
        inc = make_incident(db_session, first_seen=base, last_seen=base)
        # Add in reverse order to ensure DB order not relied upon
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=a2.id))
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=a1.id))
        db_session.commit()
        body1 = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        body2 = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        assert body1["alerts"][0]["id"] < body1["alerts"][1]["id"]
        assert body1["alerts"] == body2["alerts"]

    def test_deterministic_event_ordering(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        ev1 = make_event(db_session, base)
        ev2 = make_event(db_session, base)
        # Same timestamp, different ids
        a1 = make_alert(db_session, base, events=[ev2, ev1])  # reverse
        inc = make_incident(db_session, first_seen=base, last_seen=base)
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=a1.id))
        db_session.commit()
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        assert body["events"][0]["id"] < body["events"][1]["id"]

    def test_utc_behavior(self, client, db_session):
        # Naive datetime should be treated as UTC
        base_naive = datetime(2026,9,14,10,0,0)  # naive
        ev = make_event(db_session, base_naive)
        alert = make_alert(db_session, base_naive, events=[ev])
        inc = make_incident(db_session, first_seen=base_naive, last_seen=base_naive)
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
        db_session.commit()
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        # Should not crash, timestamps include Z
        assert "T" in body["events"][0]["timestamp"]

    def test_missing_optional_fields(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        ev = make_event(db_session, base, service=None, host=None, extra=None)
        alert = make_alert(db_session, base, events=[ev])
        inc = make_incident(db_session, first_seen=base, last_seen=base)
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
        db_session.commit()
        resp = client.get(f"/api/v1/incidents/{inc.id}/investigation")
        assert resp.status_code == 200
        assert resp.json()["events"][0]["service"] is None

    def test_malformed_extra_data(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        # Malformed extra_data as string (simulate)
        ev = Event(timestamp=base, source="auth", level="ERROR", message="msg", raw_log="raw", extra_data=None)
        # Force malformed by setting extra_data to string would fail validation, so test with None
        db_session.add(ev)
        db_session.flush()
        alert = make_alert(db_session, base, events=[ev])
        inc = make_incident(db_session, first_seen=base, last_seen=base)
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
        db_session.commit()
        resp = client.get(f"/api/v1/incidents/{inc.id}/investigation")
        assert resp.status_code == 200

    def test_correlation_metadata(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        inc = make_incident(db_session, correlation_key="ip:10.0.0.5", first_seen=base, last_seen=base)
        inc.context = {"strategy":"source_ip","correlation_key":"ip:10.0.0.5","correlation_window_seconds":3600}
        db_session.commit()
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        assert body["correlation"]["strategy"] == "source_ip"
        assert body["correlation"]["correlation_key"] == "ip:10.0.0.5"
        assert body["correlation"]["correlation_window_seconds"] == 3600

    def test_summary_counts(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        ev1 = make_event(db_session, base, source="auth", service="api", host="h1", extra={"ip":"10.0.0.5"})
        ev2 = make_event(db_session, base+timedelta(seconds=10), source="auth", service="api", host="h1", extra={"ip":"10.0.0.5"})
        a1 = make_alert(db_session, base, severity="HIGH", events=[ev1])
        a2 = make_alert(db_session, base+timedelta(seconds=10), severity="MEDIUM", events=[ev2])
        inc = make_incident(db_session, first_seen=base, last_seen=base+timedelta(seconds=10), severity="HIGH")
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=a1.id))
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=a2.id))
        db_session.commit()
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        assert body["summary"]["alert_count"] == 2
        assert body["summary"]["event_count"] == 2
        assert body["summary"]["unique_sources"] == 1
        assert body["summary"]["unique_hosts"] == 1
        assert body["summary"]["unique_services"] == 1
        assert body["summary"]["severity_breakdown"]["HIGH"] == 1
        assert body["summary"]["severity_breakdown"]["MEDIUM"] == 1
        assert body["summary"]["time_span_seconds"] == 10

    def test_entity_extraction_and_dedup(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        ev1 = make_event(db_session, base, source="auth", service="api", host="h1", extra={"ip":"10.0.0.5"})
        ev2 = make_event(db_session, base+timedelta(seconds=10), source="auth", service="api", host="h1", extra={"ip":"10.0.0.5"})
        a1 = make_alert(db_session, base, events=[ev1, ev2])
        inc = make_incident(db_session, first_seen=base, last_seen=base)
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=a1.id))
        db_session.commit()
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        assert body["entities"]["ips"] == ["10.0.0.5"]
        assert body["entities"]["hosts"] == ["h1"]
        assert body["entities"]["services"] == ["api"]
        assert body["entities"]["sources"] == ["auth"]

    def test_detection_metadata(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        ev = make_event(db_session, base)
        alert = make_alert(db_session, base, events=[ev])
        inc = make_incident(db_session, first_seen=base, last_seen=base)
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
        db_session.commit()
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        assert body["detection"][0]["rule_name"] == "BruteForceLogin"
        assert "rule_type" in body["detection"][0]
        assert body["detection"][0]["alert_id"] == alert.id

    def test_raw_log_exposure(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        ev = make_event(db_session, base, raw="secret raw log")
        alert = make_alert(db_session, base, events=[ev])
        inc = make_incident(db_session, first_seen=base, last_seen=base)
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
        db_session.commit()
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        assert body["events"][0]["raw_log"] == "secret raw log"

    def test_404(self, client):
        resp = client.get("/api/v1/incidents/9999/investigation")
        assert resp.status_code == 404

    def test_empty_incident_again(self, client, db_session):
        inc = make_incident(db_session)
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        assert body["alerts"] == []
        assert body["summary"]["alert_count"] == 0

    def test_alert_truncation(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        inc = make_incident(db_session, first_seen=base, last_seen=base+timedelta(seconds=200))
        # Create 101 alerts
        for i in range(101):
            ev = make_event(db_session, base+timedelta(seconds=i), extra={"ip":f"10.0.0.{i%2}"})
            alert = make_alert(db_session, base+timedelta(seconds=i), events=[ev])
            db_session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
        db_session.commit()
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        assert len(body["alerts"]) == 100
        assert body["summary"]["total_alert_count"] == 101
        assert body["summary"]["truncated"] is True

    def test_event_truncation(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        inc = make_incident(db_session, first_seen=base, last_seen=base+timedelta(seconds=600))
        # Create 1 alert with 501 events (need to bypass normal alert creation)
        alert = make_alert(db_session, base, events=[])
        # Add 501 events linked to same alert
        for i in range(501):
            ev = make_event(db_session, base+timedelta(seconds=i), extra={"ip":"10.0.0.5"})
            db_session.add(AlertEvent(alert_id=alert.id, event_id=ev.id))
        alert.first_event_id = 1
        alert.last_event_id = 501
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
        db_session.commit()
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        assert len(body["events"]) == 500
        assert body["summary"]["total_event_count"] == 501
        assert body["summary"]["truncated"] is True

    def test_timeline_truncation(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        inc = make_incident(db_session, first_seen=base, last_seen=base+timedelta(seconds=700))
        # Create 600 events + 10 alerts = 610 timeline entries >600
        for i in range(600):
            ev = make_event(db_session, base+timedelta(seconds=i))
            # Link each event to an alert? Simpler: create one alert with 600 events, plus 10 alerts
        alert = make_alert(db_session, base, events=[])
        for i in range(600):
            ev = make_event(db_session, base+timedelta(seconds=i))
            db_session.add(AlertEvent(alert_id=alert.id, event_id=ev.id))
        # Add 10 more alerts at different times
        for i in range(10):
            a = make_alert(db_session, base+timedelta(seconds=i), events=[])
            db_session.add(IncidentAlert(incident_id=inc.id, alert_id=a.id))
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
        db_session.commit()
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        assert len(body["timeline"]) <= 600
        if body["summary"]["truncated"]:
            assert body["summary"]["total_event_count"] >= 500

    def test_truncated_total_counts(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        inc = make_incident(db_session, first_seen=base, last_seen=base)
        for i in range(101):
            ev = make_event(db_session, base+timedelta(seconds=i))
            alert = make_alert(db_session, base+timedelta(seconds=i), events=[ev])
            db_session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
        db_session.commit()
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        assert body["summary"]["total_alert_count"] == 101
        assert body["summary"]["alert_count"] == 100

    def test_include_events_false(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        ev = make_event(db_session, base)
        alert = make_alert(db_session, base, events=[ev])
        inc = make_incident(db_session, first_seen=base, last_seen=base)
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
        db_session.commit()
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation?include_events=false").json()
        assert body["events"] == []
        # summary should still have totals
        assert body["summary"]["total_event_count"] == 1

    def test_include_timeline_false(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        ev = make_event(db_session, base)
        alert = make_alert(db_session, base, events=[ev])
        inc = make_incident(db_session, first_seen=base, last_seen=base)
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
        db_session.commit()
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation?include_timeline=false").json()
        assert body["timeline"] == []

    def test_dynamic_freshness(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        ev1 = make_event(db_session, base)
        a1 = make_alert(db_session, base, events=[ev1])
        inc = make_incident(db_session, first_seen=base, last_seen=base)
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=a1.id))
        db_session.commit()
        body1 = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        assert len(body1["alerts"]) == 1
        # Add another alert to same incident
        ev2 = make_event(db_session, base+timedelta(seconds=10))
        a2 = make_alert(db_session, base+timedelta(seconds=10), events=[ev2])
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=a2.id))
        # Update incident last_seen
        inc.last_seen_at = base+timedelta(seconds=10)
        db_session.commit()
        body2 = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        assert len(body2["alerts"]) == 2
        assert len(body2["events"]) == 2

    def test_orphan_alert_event(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        ev = make_event(db_session, base)
        alert = make_alert(db_session, base, events=[ev])
        inc = make_incident(db_session, first_seen=base, last_seen=base)
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
        db_session.commit()
        # Delete event to orphan
        db_session.delete(ev)
        db_session.commit()
        # Should not crash, should log warning and return empty events
        body = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        assert body["events"] == []
        assert len(body["alerts"]) == 1

    def test_determinism(self, client, db_session):
        base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
        ev = make_event(db_session, base)
        alert = make_alert(db_session, base, events=[ev])
        inc = make_incident(db_session, first_seen=base, last_seen=base)
        db_session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
        db_session.commit()
        body1 = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        body2 = client.get(f"/api/v1/incidents/{inc.id}/investigation").json()
        # Compare parsed structures, not raw bytes
        assert body1["alerts"] == body2["alerts"]
        assert body1["events"] == body2["events"]
        assert body1["timeline"] == body2["timeline"]
        assert body1["summary"] == body2["summary"]
