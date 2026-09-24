"""Tests for the threat assessment service and API."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import event as sa_event

from app.db.base import Base
from app.models.detection_rule import DetectionRule
from app.models.event import Event
from app.normalizers.event_normalizer import EventNormalizer
from app.services.detection import ensure_default_rules
from app.services.ingestion import IngestionService
from app.services.threat_assessment import ThreatAssessmentService
from app.detection.registry import rule_registry
from app.parsers.json_parser import JSONParser
from app.parsers.keyvalue_parser import KeyValueParser
from app.parsers.text_parser import TextParser
from app.parsers.registry import parser_registry
from app.synthetic import scenarios as syn

from tests.test_detection_fixtures import _register_all as _register_all_rules


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
    _register_all_rules(session)
    parser_registry.reset()
    parser_registry.register(JSONParser())
    parser_registry.register(KeyValueParser())
    parser_registry.register(TextParser(), is_fallback=True)
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
        parser_registry.reset()
        rule_registry.clear_all()


def _ingest(db, lines):
    svc = IngestionService(normalizer=EventNormalizer(default_source="test"))
    results = svc.ingest_batch(list(lines), db)
    db.commit()
    return results


class TestThreatAssessmentService:
    def test_empty_produces_low_no_threat(self, db_session):
        svc = ThreatAssessmentService()
        assessment = svc.assess(db=db_session)
        assert assessment.threat_level == "LOW"
        assert assessment.alerts_count == 0
        assert assessment.incidents_count == 0
        assert "no configured" in assessment.explanation.lower()

    def test_bruteforce_produces_high(self, db_session):
        lines = syn.generate("authentication_attack", seed=31)
        _ingest(db_session, lines)
        svc = ThreatAssessmentService()
        assessment = svc.assess(db=db_session, window_seconds=300)
        assert assessment.alerts_count >= 1
        assert assessment.threat_level in ("HIGH", "CRITICAL", "MEDIUM")
        assert assessment.details, "explanation details must come from real alerts"

    def test_malware_produces_critical(self, db_session):
        lines = syn.generate("malware_detection", seed=32)
        _ingest(db_session, lines)
        svc = ThreatAssessmentService()
        assessment = svc.assess(db=db_session, window_seconds=300)
        assert assessment.alerts_count >= 1
        # MalwareDetection severity is CRITICAL in defaults
        assert assessment.threat_level == "CRITICAL"

    def test_synthetic_flag_passthrough(self, db_session):
        lines = syn.generate("mostly_normal", seed=33)
        _ingest(db_session, lines)
        svc = ThreatAssessmentService()
        assessment = svc.assess(db=db_session, synthetic=True)
        assert assessment.synthetic is True
        assert assessment.alerts_count == 0

    def test_multistage_correlates_to_incident(self, db_session):
        lines = syn.generate("multi_stage_incident", seed=42)
        _ingest(db_session, lines)
        svc = ThreatAssessmentService()
        assessment = svc.assess(db=db_session, window_seconds=3600, correlation_window_seconds=3600)
        assert assessment.alerts_count >= 4
        assert assessment.incidents_count >= 1
        assert assessment.events_analyzed >= len(lines) - 5

    def test_scoped_assessment_finds_old_timestamp_batch(self, db_session):
        """Uploads with their own (old) timestamps are analyzed via scoping."""
        from datetime import timedelta

        old_base = datetime.now(timezone.utc) - timedelta(days=2)
        lines = syn.generate("authentication_attack", seed=51)
        # Rewrite timestamps to two days ago (outside any default window).
        import json

        old_lines = []
        for i, line in enumerate(lines):
            obj = json.loads(line)
            obj["timestamp"] = (old_base + timedelta(seconds=i * 5)).isoformat().replace("+00:00", "Z")
            old_lines.append(json.dumps(obj))
        results = _ingest(db_session, old_lines)
        event_ids = [r.event_id for r in results if r.event_id is not None]
        assert len(event_ids) == len(old_lines)

        svc = ThreatAssessmentService()
        # Unscoped run anchored at server now finds nothing for this batch.
        unscoped = svc.assess(db=db_session, window_seconds=300)
        assert unscoped.alerts_count == 0
        # Scoped run anchors at the batch and detects the brute force.
        scoped = svc.assess(db=db_session, window_seconds=300, event_ids=event_ids)
        assert scoped.alerts_count >= 1
        assert scoped.events_analyzed == len(old_lines)
        assert scoped.threat_level in ("MEDIUM", "HIGH", "CRITICAL")

    def test_scoped_assessment_unknown_ids_useful_result(self, db_session):
        svc = ThreatAssessmentService()
        assessment = svc.assess(db=db_session, event_ids=[999001, 999002])
        assert assessment.threat_level == "LOW"
        assert assessment.alerts_count == 0
        assert assessment.events_analyzed == 0
        assert "not found" in assessment.explanation.lower()

    def test_scoped_assessment_empty_ids_useful_result(self, db_session):
        svc = ThreatAssessmentService()
        assessment = svc.assess(db=db_session, event_ids=[])
        assert assessment.threat_level == "LOW"
        assert assessment.alerts_count == 0
        assert assessment.events_analyzed == 0

    def test_scoped_sweep_finds_early_attack_in_long_upload(self, db_session):
        """A 60s attack early in a 14-minute upload is still detected.

        Rules anchor at evaluation time; without sweeping, an attack older
        than the rule window relative to the newest event would be missed.
        """
        from app.models.event import Event

        base = datetime(2026, 9, 24, 14, 21, 11, tzinfo=timezone.utc)
        for i in range(5):
            db_session.add(Event(
                timestamp=base + timedelta(seconds=3 * i),
                source="auth.service", level="ERROR", message="Failed login",
                raw_log="raw", extra_data={"ip": "10.20.30.99"},
            ))
        # Trailing noise 14 minutes later (becomes the newest event).
        db_session.add(Event(
            timestamp=base + timedelta(seconds=840),
            source="system", level="INFO", message="heartbeat",
            raw_log="raw", extra_data={},
        ))
        db_session.commit()
        ids = [e.id for e in db_session.execute(select(Event)).scalars().all()]

        svc = ThreatAssessmentService()
        scoped = svc.assess(db=db_session, window_seconds=3600, event_ids=ids)
        assert scoped.alerts_count >= 1
        assert scoped.threat_level == "HIGH"

    def test_scoped_explicit_evaluation_time_single_run(self, db_session):
        """An explicitly passed evaluation_time keeps legacy single-run behavior."""
        from app.models.event import Event

        base = datetime(2026, 9, 24, 14, 21, 11, tzinfo=timezone.utc)
        for i in range(5):
            db_session.add(Event(
                timestamp=base + timedelta(seconds=3 * i),
                source="auth.service", level="ERROR", message="Failed login",
                raw_log="raw", extra_data={"ip": "10.20.30.99"},
            ))
        db_session.add(Event(
            timestamp=base + timedelta(seconds=840),
            source="system", level="INFO", message="heartbeat",
            raw_log="raw", extra_data={},
        ))
        db_session.commit()
        ids = [e.id for e in db_session.execute(select(Event)).scalars().all()]

        svc = ThreatAssessmentService()
        scoped = svc.assess(
            db=db_session, window_seconds=3600, event_ids=ids,
            evaluation_time=base + timedelta(seconds=840),
        )
        assert scoped.alerts_count == 0

    def test_scoped_assessment_reports_only_current_incidents(self, db_session):
        from app.services.detection import DetectionService
        from app.detection.engine import DetectionEngine
        from app.services.incident_correlation import IncidentCorrelationService

        # First batch creates an incident.
        lines_a = syn.generate("authentication_attack", seed=61)
        results_a = _ingest(db_session, lines_a)
        ids_a = [r.event_id for r in results_a if r.event_id is not None]
        svc = ThreatAssessmentService()
        first = svc.assess(db=db_session, window_seconds=3600, correlation_window_seconds=3600, event_ids=ids_a)
        assert first.incidents_count >= 1

        # Second, benign batch: scoped assessment must not report the old incident.
        lines_b = syn.generate("mostly_normal", seed=62)
        results_b = _ingest(db_session, lines_b)
        ids_b = [r.event_id for r in results_b if r.event_id is not None]
        second = svc.assess(db=db_session, window_seconds=3600, correlation_window_seconds=3600, event_ids=ids_b)
        assert second.alerts_count == 0
        assert second.incidents_count == 0
        assert second.events_analyzed == len(ids_b)


class TestThreatAssessmentAPI:
    def test_api_returns_assessment(self, client, db_session):
        lines = syn.generate("authentication_attack", seed=41)
        _ingest(db_session, lines)
        resp = client.post("/api/v1/threat-assessment", json={"window_seconds": 300, "synthetic": True})
        assert resp.status_code == 200
        body = resp.json()
        assert body["threat_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert body["alerts_count"] >= 1
        assert body["synthetic"] is True
        assert isinstance(body["details"], list)

    def test_api_no_threat(self, client):
        resp = client.post("/api/v1/threat-assessment", json={"window_seconds": 300})
        assert resp.status_code == 200
        body = resp.json()
        assert body["alerts_count"] == 0
        assert body["incidents_count"] == 0

    def test_api_rejects_naive_evaluation_time(self, client):
        resp = client.post("/api/v1/threat-assessment", json={"evaluation_time": "2026-09-22T10:00:00"})
        assert resp.status_code == 422

    def test_api_rejects_bad_strategy(self, client):
        resp = client.post("/api/v1/threat-assessment", json={"correlation_strategy": "nope"})
        assert resp.status_code == 422

    def test_api_scoped_assessment_uses_event_ids(self, client, db_session):
        import json
        from datetime import timedelta

        old_base = datetime.now(timezone.utc) - timedelta(days=3)
        lines = syn.generate("authentication_attack", seed=71)
        old_lines = []
        for i, line in enumerate(lines):
            obj = json.loads(line)
            obj["timestamp"] = (old_base + timedelta(seconds=i * 5)).isoformat().replace("+00:00", "Z")
            old_lines.append(json.dumps(obj))
        results = _ingest(db_session, old_lines)
        event_ids = [r.event_id for r in results if r.event_id is not None]
        resp = client.post(
            "/api/v1/threat-assessment",
            json={"window_seconds": 300, "event_ids": event_ids, "synthetic": True},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["alerts_count"] >= 1
        assert body["events_analyzed"] == len(event_ids)
        # Deep-link IDs are consistent with the reported counts.
        assert len(body["alert_ids"]) == body["alerts_count"]
        assert len(body["incident_ids"]) == body["incidents_count"]
        if body["incident_ids"]:
            inc = client.get(f"/api/v1/incidents/{body['incident_ids'][0]}")
            assert inc.status_code == 200

    def test_api_rejects_invalid_event_ids(self, client):
        resp = client.post("/api/v1/threat-assessment", json={"event_ids": [0, -5]})
        assert resp.status_code == 422
        resp = client.post("/api/v1/threat-assessment", json={"event_ids": list(range(1, 10002))})
        assert resp.status_code == 422

    def test_api_unknown_event_ids_useful_result(self, client):
        resp = client.post("/api/v1/threat-assessment", json={"event_ids": [987001]})
        assert resp.status_code == 200
        body = resp.json()
        assert body["alerts_count"] == 0
        assert body["events_analyzed"] == 0
