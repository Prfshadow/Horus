"""Tests for synthetic threat-lab scenario generators.

Generators must produce ingestion-compatible raw JSON log lines marked
synthetic/demo, using only documentation IP ranges and no secrets.
"""

import json
from datetime import datetime, timezone

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
from app.detection.engine import DetectionEngine
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
    svc = IngestionService(normalizer=EventNormalizer(default_source="synthetic-test"))
    results = svc.ingest_batch(list(lines), db)
    db.commit()
    return results


class TestScenarioValidity:
    def test_all_generators_return_parseable_marked_lines(self):
        for name in syn.SCENARIO_NAMES:
            lines = syn.generate(name, seed=7)
            assert len(lines) >= 2, name
            for line in lines:
                obj = json.loads(line)
                assert obj.get("synthetic") is True, name
                assert obj.get("scenario") in syn.SCENARIO_NAMES + ["mostly_normal"] or name == "random", name
                assert "timestamp" in obj and "message" in obj, name

    def test_timestamps_recent_and_ordered(self):
        now = datetime.now(timezone.utc)
        for name in syn.SCENARIO_NAMES:
            lines = syn.generate(name, seed=11)
            times = [datetime.fromisoformat(json.loads(l)["timestamp"].replace("Z", "+00:00")) for l in lines]
            assert times == sorted(times), name
            assert (now - times[-1]).total_seconds() < 600, name
            assert (now - times[0]).total_seconds() < 600, name

    def test_only_documentation_ips(self):
        import re

        ip_re = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
        for name in syn.SCENARIO_NAMES:
            for line in syn.generate(name, seed=13):
                for ip in ip_re.findall(line):
                    assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "10.")), f"{name}: {ip}"

    def test_no_secrets_or_exploit_payloads(self):
        forbidden = ["password=", "passwd", "api_key", "BEGIN PRIVATE", "<script", "UNION SELECT",
                     "DROP TABLE", "/etc/passwd", "mimikatz", "meterpreter"]
        for name in syn.SCENARIO_NAMES:
            for line in syn.generate(name, seed=17):
                lowered = line.lower()
                for bad in forbidden:
                    assert bad.lower() not in lowered, f"{name} contains {bad}"

    def test_random_scenario_valid(self):
        name, lines = syn.random_scenario(seed=3)
        assert name in syn.SCENARIO_NAMES
        assert len(lines) >= 2
        for line in lines:
            assert json.loads(line)["synthetic"] is True

    def test_unknown_scenario_rejected(self):
        with pytest.raises(ValueError):
            syn.generate("not_a_scenario")

    def test_multistage_contains_expected_stages(self):
        blob = "\n".join(syn.generate("multi_stage_incident", seed=42))
        assert "login_failed" in blob
        assert "login_success" in blob
        assert "Domain Admins" in blob
        assert "powershell" in blob
        assert "evil.example" in blob
        assert "bytes_sent" in blob


class TestScenarioPipeline:
    def test_ingestion_stores_synthetic_marked_events(self, db_session):
        lines = syn.generate("authentication_attack", seed=21)
        results = _ingest(db_session, lines)
        assert all(r.status == "stored" for r in results)
        events = db_session.execute(select(Event)).scalars().all()
        assert len(events) == len(lines)
        for ev in events:
            assert ev.raw_log in lines  # raw preserved
            assert ev.extra_data.get("synthetic") is True

    def test_authentication_attack_triggers_bruteforce(self, db_session):
        lines = syn.generate("authentication_attack", seed=22)
        _ingest(db_session, lines)
        engine = DetectionEngine()
        matches = engine.scan_recent(db=db_session, window_seconds=300, rule_names=["BruteForceLogin"])
        assert len(matches) >= 1

    def test_mostly_normal_triggers_nothing(self, db_session):
        lines = syn.generate("mostly_normal", seed=23)
        _ingest(db_session, lines)
        engine = DetectionEngine()
        matches = engine.scan_recent(db=db_session, window_seconds=300)
        assert matches == []

    def test_multistage_end_to_end_alerts_and_correlation(self, db_session):
        from app.services.incident_correlation import IncidentCorrelationService

        lines = syn.generate("multi_stage_incident", seed=42)
        _ingest(db_session, lines)
        engine = DetectionEngine()
        matches = engine.scan_recent(db=db_session, window_seconds=3600)
        rule_names = {m["rule_model"].name for m in matches}
        assert len(matches) >= 4, rule_names
        assert "AccountTakeover" in rule_names
        assert "PrivilegeEscalation" in rule_names

        from app.services.detection import DetectionService
        from datetime import timedelta

        svc = DetectionService(engine=engine)
        alerts = svc.run_detection(db=db_session, window_seconds=3600)
        assert len(alerts) >= 4
        corr = IncidentCorrelationService().run_correlation(db=db_session, window_seconds=3600)
        assert corr["incidents_created"] >= 1
