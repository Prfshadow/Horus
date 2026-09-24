"""Tests for SQLInjection, XSSAttempt, MalwareDetection rules."""

from datetime import datetime, timedelta, timezone

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
from app.models.detection_rule import DetectionRule
from app.services.detection import DetectionService, ensure_default_rules
from app.detection.engine import DetectionEngine
from app.detection.registry import rule_registry
from app.detection.rules.brute_force import BruteForceLoginRule
from app.detection.rules.error_spike import ErrorSpikeRule
from app.detection.rules.port_scan import PortScanRule
from app.detection.rules.web_scan import WebScanRule
from app.detection.rules.authentication_anomaly import AuthenticationAnomalyRule
from app.detection.rules.sql_injection import SQLInjectionRule
from app.detection.rules.xss_attempt import XSSAttemptRule
from app.detection.rules.malware_detection import MalwareDetectionRule

BASE = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)


def _register_all(db_session):
    rule_registry.clear_all()
    rule_registry.register_class("threshold", BruteForceLoginRule)
    rule_registry.register_class("frequency", ErrorSpikeRule)
    rule_registry.register_class("port_scan", PortScanRule)
    rule_registry.register_class("web_scan", WebScanRule)
    rule_registry.register_class("authentication_anomaly", AuthenticationAnomalyRule)
    rule_registry.register_class("sql_injection", SQLInjectionRule)
    rule_registry.register_class("xss_attempt", XSSAttemptRule)
    rule_registry.register_class("malware_detection", MalwareDetectionRule)
    for rm in db_session.execute(select(DetectionRule)).scalars().all():
        cls = rule_registry.get_class(rm.rule_type)
        if cls:
            inst = cls(config=rm.config)
            inst.name = rm.name
            rule_registry.register_instance(rm.name, inst)


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
    _register_all(session)
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
        rule_registry.clear_all()


@pytest.fixture()
def client(db_session):
    app = create_app()

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        _register_all(db_session)
        yield c
    app.dependency_overrides.clear()
    rule_registry.clear_all()


def insert_events(db: Session, events_data: list[dict]) -> list[Event]:
    evs = []
    for d in events_data:
        e = Event(**d)
        db.add(e)
        evs.append(e)
    db.commit()
    for e in evs:
        db.refresh(e)
    return evs


def ev(ts, extra=None, message="GET /search?q=hello", source="web", level="INFO"):
    return {
        "timestamp": ts,
        "source": source,
        "level": level,
        "message": message,
        "raw_log": "raw",
        "extra_data": extra,
    }


def scan(db_session, rule_name, **kwargs):
    engine = DetectionEngine()
    results = engine.scan_recent(db=db_session, **kwargs)
    return [r for r in results if r["rule_model"].name == rule_name]


class TestSQLInjection:
    def test_structured_attack_type(self, db_session):
        evs = insert_events(
            db_session,
            [ev(BASE, extra={"ip": "203.0.113.20", "attack_type": "sqli", "path": "/search", "payload": "q=1"})],
        )
        matches = scan(db_session, "SQLInjection", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        m = matches[0]["match"]
        assert m.context["rule_type"] == "sql_injection"
        assert m.context["indicator"] == "structured:attack_type"
        assert sorted(m.evidence_event_ids) == sorted(e.id for e in evs)
        assert matches[0]["rule_model"].severity == "HIGH"
        assert "SQL injection attempt detected" in m.summary

    def test_waf_rule_id(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, extra={"ip": "203.0.113.21", "rule": "ModSecurity 942100 SQL Injection Attack"})],
        )
        matches = scan(db_session, "SQLInjection", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        assert matches[0]["match"].context["indicator"] == "structured:rule"

    def test_payload_union_select(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, extra={"ip": "203.0.113.22", "payload": "id=1 UNION SELECT password FROM users"})],
        )
        matches = scan(db_session, "SQLInjection", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        assert matches[0]["match"].context["indicator"] == "payload-signature"

    def test_benign_select_no_trigger(self, db_session):
        insert_events(
            db_session,
            [
                ev(BASE + timedelta(seconds=i), extra={"ip": "203.0.113.23", "payload": "select your plan to continue"})
                for i in range(5)
            ],
        )
        matches = scan(db_session, "SQLInjection", window_seconds=300, evaluation_time=BASE + timedelta(seconds=300))
        assert len(matches) == 0

    def test_benign_union_word_no_trigger(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, message="union meeting at noon in the lobby", extra={"ip": "203.0.113.24"})],
        )
        matches = scan(db_session, "SQLInjection", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_outside_window(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, extra={"ip": "203.0.113.25", "attack_type": "sql_injection"})],
        )
        matches = scan(db_session, "SQLInjection", window_seconds=60, evaluation_time=BASE + timedelta(seconds=3600))
        assert len(matches) == 0

    def test_missing_fields_no_crash(self, db_session):
        insert_events(
            db_session,
            [
                ev(BASE, extra=None),
                ev(BASE, extra="oops"),
                ev(BASE, extra={"payload": 12345}),
                ev(BASE, extra={"attack_type": "  "}),
            ],
        )
        matches = scan(db_session, "SQLInjection", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_case_insensitive_attack_type(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, extra={"ip": "203.0.113.26", "attack_type": "SQL-Injection"})],
        )
        matches = scan(db_session, "SQLInjection", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1

    def test_cooldown_dedup(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, extra={"ip": "203.0.113.27", "attack_type": "sqli"})],
        )
        svc = DetectionService(engine=DetectionEngine())
        first = svc.run_detection(db=db_session, window_seconds=300, evaluation_time=BASE + timedelta(seconds=60), rule_names=["SQLInjection"])
        assert len(first) == 1
        second = svc.run_detection(db=db_session, window_seconds=300, evaluation_time=BASE + timedelta(seconds=61), rule_names=["SQLInjection"])
        assert len(second) == 0


class TestXSSAttempt:
    def test_structured_attack_type(self, db_session):
        evs = insert_events(
            db_session,
            [ev(BASE, extra={"ip": "198.51.100.30", "attack_type": "xss", "payload": "<script>alert(1)</script>"})],
        )
        matches = scan(db_session, "XSSAttempt", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        m = matches[0]["match"]
        assert m.context["rule_type"] == "xss_attempt"
        assert m.context["indicator"] == "structured:attack_type"
        assert sorted(m.evidence_event_ids) == sorted(e.id for e in evs)
        assert matches[0]["rule_model"].severity == "HIGH"
        assert "Cross-site scripting attempt detected" in m.summary

    def test_security_rule_field(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, extra={"ip": "198.51.100.31", "security_rule": "WAF-XSS-Block"})],
        )
        matches = scan(db_session, "XSSAttempt", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1

    def test_payload_script_tag(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, extra={"ip": "198.51.100.32", "parameter": "q", "payload": '"><ScRiPt>alert(document.cookie)</ScRiPt>'})],
        )
        matches = scan(db_session, "XSSAttempt", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        assert matches[0]["match"].context["indicator"] == "payload-signature"

    def test_benign_script_word_no_trigger(self, db_session):
        insert_events(
            db_session,
            [
                ev(BASE + timedelta(seconds=i), message="deployment script finished", extra={"ip": "198.51.100.33"})
                for i in range(5)
            ],
        )
        matches = scan(db_session, "XSSAttempt", window_seconds=300, evaluation_time=BASE + timedelta(seconds=300))
        assert len(matches) == 0

    def test_benign_html_no_trigger(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, extra={"ip": "198.51.100.34", "payload": "<b>hello</b> world"})],
        )
        matches = scan(db_session, "XSSAttempt", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_outside_window(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, extra={"ip": "198.51.100.35", "attack_type": "xss"})],
        )
        matches = scan(db_session, "XSSAttempt", window_seconds=60, evaluation_time=BASE + timedelta(seconds=3600))
        assert len(matches) == 0

    def test_missing_fields_no_crash(self, db_session):
        insert_events(
            db_session,
            [
                ev(BASE, extra=None),
                ev(BASE, extra={"payload": None}),
                ev(BASE, extra="oops"),
            ],
        )
        matches = scan(db_session, "XSSAttempt", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_cooldown_dedup(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, extra={"ip": "198.51.100.36", "attack_type": "xss"})],
        )
        svc = DetectionService(engine=DetectionEngine())
        first = svc.run_detection(db=db_session, window_seconds=300, evaluation_time=BASE + timedelta(seconds=60), rule_names=["XSSAttempt"])
        assert len(first) == 1
        second = svc.run_detection(db=db_session, window_seconds=300, evaluation_time=BASE + timedelta(seconds=61), rule_names=["XSSAttempt"])
        assert len(second) == 0


class TestMalwareDetection:
    def test_explicit_verdict(self, db_session):
        evs = insert_events(
            db_session,
            [ev(BASE, source="endpoint", extra={"detection_type": "ransomware_detected", "threat_name": "BlackCat"}, message="threat blocked")],
        )
        # host missing -> falls back gracefully; still fires
        matches = scan(db_session, "MalwareDetection", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        m = matches[0]["match"]
        assert m.context["rule_type"] == "malware_detection"
        assert m.context["indicator"] == "verdict"
        assert sorted(m.evidence_event_ids) == sorted(e.id for e in evs)
        assert matches[0]["rule_model"].severity == "CRITICAL"
        assert "Malware verdict reported" in m.summary

    def test_threat_family_name(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, source="endpoint", extra={"threat_name": "Trojan:Win32/Wacatac"})],
        )
        matches = scan(db_session, "MalwareDetection", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1

    def test_filename_alone_no_trigger(self, db_session):
        insert_events(
            db_session,
            [
                ev(BASE + timedelta(seconds=i), source="endpoint", extra={"filename": "setup.exe", "file_path": "C:\\temp\\evil.exe"})
                for i in range(5)
            ],
        )
        matches = scan(db_session, "MalwareDetection", window_seconds=300, evaluation_time=BASE + timedelta(seconds=300))
        assert len(matches) == 0

    def test_antivirus_word_no_trigger(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, source="endpoint", extra={"threat_name": "antivirus scan completed"})],
        )
        matches = scan(db_session, "MalwareDetection", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_malware_word_in_message_no_trigger(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, source="endpoint", message="malware scan started, all clean")],
        )
        matches = scan(db_session, "MalwareDetection", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_outside_window(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, source="endpoint", extra={"verdict": "malicious"})],
        )
        matches = scan(db_session, "MalwareDetection", window_seconds=60, evaluation_time=BASE + timedelta(seconds=3600))
        assert len(matches) == 0

    def test_missing_fields_no_crash(self, db_session):
        insert_events(
            db_session,
            [
                ev(BASE, extra=None),
                ev(BASE, extra="oops"),
                ev(BASE, extra={"verdict": 123}),
            ],
        )
        matches = scan(db_session, "MalwareDetection", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_cooldown_dedup(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, source="endpoint", extra={"verdict": "malicious"})],
        )
        svc = DetectionService(engine=DetectionEngine())
        first = svc.run_detection(db=db_session, window_seconds=300, evaluation_time=BASE + timedelta(seconds=60), rule_names=["MalwareDetection"])
        assert len(first) == 1
        second = svc.run_detection(db=db_session, window_seconds=300, evaluation_time=BASE + timedelta(seconds=61), rule_names=["MalwareDetection"])
        assert len(second) == 0
