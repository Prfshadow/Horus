"""Tests for POST /api/v1/admin/reset (dev data reset)."""

from datetime import datetime, timezone

from sqlalchemy import func, select

from app.models.alert import Alert
from app.models.alert_event import AlertEvent
from app.models.detection_rule import DetectionRule
from app.models.event import Event
from app.models.incident import Incident
from app.models.incident_alert import IncidentAlert


def _seed_pipeline(db_session):
    base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    ev1 = Event(timestamp=base, source="auth", level="ERROR", message="fail 1", raw_log="raw 1", extra_data={"ip": "10.0.0.5"})
    ev2 = Event(timestamp=base, source="auth", level="ERROR", message="fail 2", raw_log="raw 2", extra_data={"ip": "10.0.0.5"})
    db_session.add_all([ev1, ev2])
    db_session.flush()
    alert = Alert(
        rule_id=1,
        rule_name="BruteForceLogin",
        status="detected",
        severity="HIGH",
        detected_at=base,
        summary="2 failed logins",
        context={"group_key": "10.0.0.5"},
        first_event_id=ev1.id,
        last_event_id=ev2.id,
    )
    db_session.add(alert)
    db_session.flush()
    db_session.add_all([
        AlertEvent(alert_id=alert.id, event_id=ev1.id),
        AlertEvent(alert_id=alert.id, event_id=ev2.id),
    ])
    inc = Incident(
        title="1 alerts for ip:10.0.0.5",
        status="open",
        severity="HIGH",
        correlation_key="ip:10.0.0.5",
        context={"strategy": "source_ip"},
        first_seen_at=base,
        last_seen_at=base,
    )
    db_session.add(inc)
    db_session.flush()
    db_session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
    db_session.commit()


def _counts(db_session):
    return {
        "events": db_session.execute(select(func.count()).select_from(Event)).scalar_one(),
        "alerts": db_session.execute(select(func.count()).select_from(Alert)).scalar_one(),
        "incidents": db_session.execute(select(func.count()).select_from(Incident)).scalar_one(),
        "alert_events": db_session.execute(select(func.count()).select_from(AlertEvent)).scalar_one(),
        "incident_alerts": db_session.execute(select(func.count()).select_from(IncidentAlert)).scalar_one(),
        "rules": db_session.execute(select(func.count()).select_from(DetectionRule)).scalar_one(),
    }


class TestAdminReset:
    def test_rejects_missing_confirmation(self, client):
        resp = client.post("/api/v1/admin/reset", json={"confirm": "yes"})
        assert resp.status_code == 400

    def test_resets_pipeline_but_keeps_rules(self, client, db_session):
        _seed_pipeline(db_session)
        before = _counts(db_session)
        assert before["events"] == 2
        assert before["alerts"] == 1
        assert before["incidents"] == 1
        assert before["rules"] >= 1

        resp = client.post("/api/v1/admin/reset", json={"confirm": "RESET"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["events_deleted"] == 2
        assert body["alerts_deleted"] == 1
        assert body["incidents_deleted"] == 1
        assert body["alert_events_deleted"] == 2
        assert body["incident_alerts_deleted"] == 1

        after = _counts(db_session)
        assert after["events"] == 0
        assert after["alerts"] == 0
        assert after["incidents"] == 0
        assert after["alert_events"] == 0
        assert after["incident_alerts"] == 0
        assert after["rules"] == before["rules"]

    def test_reset_empty_reports_zeros(self, client):
        resp = client.post("/api/v1/admin/reset", json={"confirm": "RESET"})
        assert resp.status_code == 200
        assert resp.json()["events_deleted"] == 0
