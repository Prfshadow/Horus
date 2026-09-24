"""Tests for DataTransferAnomaly and AccountTakeover rules."""

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
from app.detection.rules.dns_anomaly import DNSAnomalyRule
from app.detection.rules.api_abuse import APIAbuseRule
from app.detection.rules.data_transfer_anomaly import DataTransferAnomalyRule
from app.detection.rules.account_takeover import AccountTakeoverRule

BASE = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
BIG = 200 * 1024 * 1024  # 200 MiB


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
    rule_registry.register_class("dns_anomaly", DNSAnomalyRule)
    rule_registry.register_class("api_abuse", APIAbuseRule)
    rule_registry.register_class("data_transfer_anomaly", DataTransferAnomalyRule)
    rule_registry.register_class("account_takeover", AccountTakeoverRule)
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


def scan(db_session, rule_name, **kwargs):
    engine = DetectionEngine()
    results = engine.scan_recent(db=db_session, **kwargs)
    return [r for r in results if r["rule_model"].name == rule_name]


class TestDataTransferAnomaly:
    def _xfer(self, ts, size, direction="outbound", dest="203.0.113.99", ip="10.0.0.5"):
        return {
            "timestamp": ts,
            "source": "firewall",
            "level": "INFO",
            "message": f"transfer {size}",
            "raw_log": "raw",
            "extra_data": {"bytes_sent": size, "direction": direction, "destination_ip": dest, "ip": ip},
        }

    def test_positive(self, db_session):
        evs = insert_events(db_session, [self._xfer(BASE, BIG)])
        matches = scan(db_session, "DataTransferAnomaly", window_seconds=3600, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        m = matches[0]["match"]
        assert m.context["rule_type"] == "data_transfer_anomaly"
        assert m.context["destination"] == "203.0.113.99"
        assert m.context["max_bytes"] == BIG
        assert m.context["direction"] == "outbound"
        assert sorted(m.evidence_event_ids) == sorted(e.id for e in evs)
        assert matches[0]["rule_model"].severity == "HIGH"
        assert "Large outbound data transfer detected" in m.summary
        assert "stolen" not in m.summary.lower()

    def test_below_threshold(self, db_session):
        insert_events(db_session, [self._xfer(BASE, 1024)])
        matches = scan(db_session, "DataTransferAnomaly", window_seconds=3600, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_inbound_direction_no_trigger(self, db_session):
        insert_events(db_session, [self._xfer(BASE, BIG, direction="inbound")])
        matches = scan(db_session, "DataTransferAnomaly", window_seconds=3600, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_unknown_direction_no_trigger(self, db_session):
        insert_events(
            db_session,
            [{"timestamp": BASE, "source": "fw", "level": "INFO", "message": "m", "raw_log": "r", "extra_data": {"bytes": BIG}}],
        )
        matches = scan(db_session, "DataTransferAnomaly", window_seconds=3600, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_large_number_elsewhere_no_trigger(self, db_session):
        insert_events(
            db_session,
            [{"timestamp": BASE, "source": "app", "level": "INFO", "message": f"processed {BIG} records", "raw_log": "r", "extra_data": {"records": BIG}}],
        )
        matches = scan(db_session, "DataTransferAnomaly", window_seconds=3600, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_outside_window(self, db_session):
        insert_events(db_session, [self._xfer(BASE, BIG)])
        matches = scan(db_session, "DataTransferAnomaly", window_seconds=60, evaluation_time=BASE + timedelta(seconds=7200))
        assert len(matches) == 0

    def test_missing_fields_no_crash(self, db_session):
        insert_events(
            db_session,
            [
                {"timestamp": BASE, "source": "fw", "level": "INFO", "message": "m", "raw_log": "r", "extra_data": None},
                {"timestamp": BASE, "source": "fw", "level": "INFO", "message": "m", "raw_log": "r", "extra_data": {"bytes_sent": "a lot", "direction": "outbound"}},
                {"timestamp": BASE, "source": "fw", "level": "INFO", "message": "m", "raw_log": "r", "extra_data": "oops"},
            ],
        )
        matches = scan(db_session, "DataTransferAnomaly", window_seconds=3600, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_grouped_by_destination(self, db_session):
        insert_events(db_session, [self._xfer(BASE, BIG, dest="203.0.113.1")])
        insert_events(db_session, [self._xfer(BASE + timedelta(seconds=10), BIG, dest="203.0.113.2")])
        matches = scan(db_session, "DataTransferAnomaly", window_seconds=3600, evaluation_time=BASE + timedelta(seconds=120))
        assert len(matches) == 2

    def test_cooldown_dedup(self, db_session):
        insert_events(db_session, [self._xfer(BASE, BIG)])
        svc = DetectionService(engine=DetectionEngine())
        first = svc.run_detection(db=db_session, window_seconds=3600, evaluation_time=BASE + timedelta(seconds=60), rule_names=["DataTransferAnomaly"])
        assert len(first) == 1
        second = svc.run_detection(db=db_session, window_seconds=3600, evaluation_time=BASE + timedelta(seconds=61), rule_names=["DataTransferAnomaly"])
        assert len(second) == 0


class TestAccountTakeover:
    def _fail(self, ts, user, ip="10.0.0.5"):
        return {
            "timestamp": ts,
            "source": "auth-service",
            "level": "ERROR",
            "message": "login failed",
            "raw_log": "raw",
            "extra_data": {"user": user, "ip": ip, "action": "login_failed"},
        }

    def _success(self, ts, user, ip="10.0.0.5"):
        return {
            "timestamp": ts,
            "source": "auth-service",
            "level": "INFO",
            "message": "login ok",
            "raw_log": "raw",
            "extra_data": {"user": user, "ip": ip, "action": "login_success"},
        }

    def test_positive_fail_then_success(self, db_session):
        data = [self._fail(BASE + timedelta(seconds=i * 10), "alice") for i in range(5)]
        data.append(self._success(BASE + timedelta(seconds=60), "alice"))
        evs = insert_events(db_session, data)
        matches = scan(db_session, "AccountTakeover", window_seconds=300, evaluation_time=BASE + timedelta(seconds=120))
        assert len(matches) == 1
        m = matches[0]["match"]
        assert m.group_key == "takeover:alice"
        assert m.context["failure_count"] == 5
        assert sorted(m.evidence_event_ids) == sorted(e.id for e in evs)
        assert matches[0]["rule_model"].severity == "HIGH"
        assert "Possible account takeover pattern" in m.summary

    def test_failures_without_success_no_trigger(self, db_session):
        insert_events(db_session, [self._fail(BASE + timedelta(seconds=i * 10), "bob") for i in range(8)])
        matches = scan(db_session, "AccountTakeover", window_seconds=300, evaluation_time=BASE + timedelta(seconds=300))
        assert len(matches) == 0

    def test_below_fail_threshold(self, db_session):
        data = [self._fail(BASE + timedelta(seconds=i * 10), "carol") for i in range(4)]
        data.append(self._success(BASE + timedelta(seconds=60), "carol"))
        insert_events(db_session, data)
        matches = scan(db_session, "AccountTakeover", window_seconds=300, evaluation_time=BASE + timedelta(seconds=120))
        assert len(matches) == 0

    def test_success_before_failures_no_trigger(self, db_session):
        data = [self._success(BASE, "dave")]
        data += [self._fail(BASE + timedelta(seconds=10 + i * 10), "dave") for i in range(5)]
        insert_events(db_session, data)
        matches = scan(db_session, "AccountTakeover", window_seconds=300, evaluation_time=BASE + timedelta(seconds=300))
        assert len(matches) == 0

    def test_different_account_success_no_trigger(self, db_session):
        data = [self._fail(BASE + timedelta(seconds=i * 10), "erin") for i in range(5)]
        data.append(self._success(BASE + timedelta(seconds=60), "frank"))
        insert_events(db_session, data)
        matches = scan(db_session, "AccountTakeover", window_seconds=300, evaluation_time=BASE + timedelta(seconds=120))
        assert len(matches) == 0

    def test_event_key_alias_for_actions(self, db_session):
        # JSON emitters using `event:` instead of `action:` behave identically.
        data = [
            {"timestamp": BASE + timedelta(seconds=i * 10), "source": "auth-service", "level": "ERROR", "message": "x",
             "raw_log": "r", "extra_data": {"user": "mallory", "ip": "10.0.0.9", "event": "login_failed"}}
            for i in range(5)
        ]
        data.append(
            {"timestamp": BASE + timedelta(seconds=60), "source": "auth-service", "level": "INFO", "message": "y",
             "raw_log": "r", "extra_data": {"user": "mallory", "ip": "10.0.0.9", "event": "login_success"}}
        )
        insert_events(db_session, data)
        matches = scan(db_session, "AccountTakeover", window_seconds=300, evaluation_time=BASE + timedelta(seconds=120))
        assert len(matches) == 1
        assert matches[0]["match"].group_key == "takeover:mallory"

    def test_warn_message_failures_count(self, db_session):
        # WARNING failures with auth-failure prose count; the success here
        # still uses a machine-readable action code.
        data = [
            {"timestamp": BASE + timedelta(seconds=i * 3), "source": "auth.service", "level": "WARNING",
             "message": "Failed login attempt username=nina ip=10.0.0.8", "raw_log": "r",
             "extra_data": {"username": "nina", "ip": "10.0.0.8"}}
            for i in range(5)
        ]
        data.append(
            {"timestamp": BASE + timedelta(seconds=60), "source": "auth-service", "level": "INFO", "message": "y",
             "raw_log": "r", "extra_data": {"user": "nina", "ip": "10.0.0.8", "action": "login_success"}}
        )
        insert_events(db_session, data)
        matches = scan(db_session, "AccountTakeover", window_seconds=300, evaluation_time=BASE + timedelta(seconds=120))
        assert len(matches) == 1
        assert matches[0]["match"].group_key == "takeover:nina"

    def test_message_only_success_no_trigger(self, db_session):
        data = [self._fail(BASE + timedelta(seconds=i * 10), "gail") for i in range(5)]
        data.append(
            {"timestamp": BASE + timedelta(seconds=60), "source": "auth", "level": "INFO", "message": "gail logged in successfully", "raw_log": "r", "extra_data": {"user": "gail", "ip": "10.0.0.5"}}
        )
        insert_events(db_session, data)
        matches = scan(db_session, "AccountTakeover", window_seconds=300, evaluation_time=BASE + timedelta(seconds=120))
        assert len(matches) == 0

    def test_missing_fields_no_crash(self, db_session):
        insert_events(
            db_session,
            [
                {"timestamp": BASE, "source": "auth", "level": "ERROR", "message": "fail", "raw_log": "r", "extra_data": None},
                {"timestamp": BASE, "source": "auth", "level": "ERROR", "message": "fail", "raw_log": "r", "extra_data": {"action": "login_failed"}},
            ],
        )
        matches = scan(db_session, "AccountTakeover", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_outside_window(self, db_session):
        data = [self._fail(BASE + timedelta(seconds=i * 10), "heidi") for i in range(5)]
        data.append(self._success(BASE + timedelta(seconds=60), "heidi"))
        insert_events(db_session, data)
        matches = scan(db_session, "AccountTakeover", window_seconds=60, evaluation_time=BASE + timedelta(seconds=3600))
        assert len(matches) == 0

    def test_cooldown_dedup(self, db_session):
        data = [self._fail(BASE + timedelta(seconds=i * 10), "ivan") for i in range(5)]
        data.append(self._success(BASE + timedelta(seconds=60), "ivan"))
        insert_events(db_session, data)
        svc = DetectionService(engine=DetectionEngine())
        first = svc.run_detection(db=db_session, window_seconds=300, evaluation_time=BASE + timedelta(seconds=120), rule_names=["AccountTakeover"])
        assert len(first) == 1
        second = svc.run_detection(db=db_session, window_seconds=300, evaluation_time=BASE + timedelta(seconds=121), rule_names=["AccountTakeover"])
        assert len(second) == 0
