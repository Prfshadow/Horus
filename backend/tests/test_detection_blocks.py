"""Tests for SecurityBlockBurst rule."""

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
from app.detection.rules.security_block_burst import SecurityBlockBurstRule

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
    rule_registry.register_class("dns_anomaly", DNSAnomalyRule)
    rule_registry.register_class("api_abuse", APIAbuseRule)
    rule_registry.register_class("data_transfer_anomaly", DataTransferAnomalyRule)
    rule_registry.register_class("account_takeover", AccountTakeoverRule)
    rule_registry.register_class("security_block_burst", SecurityBlockBurstRule)
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


def _block(ts, ip="203.0.113.50", port=443, action="blocked"):
    return {
        "timestamp": ts,
        "source": "firewall",
        "level": "WARNING",
        "message": f"{action} {ip}",
        "raw_log": "raw",
        "extra_data": {"action": action, "source_ip": ip, "destination_port": port},
    }


class TestSecurityBlockBurst:
    def test_positive(self, db_session):
        evs = insert_events(db_session, [_block(BASE + timedelta(seconds=i), port=1000 + i) for i in range(20)])
        matches = scan(db_session, "SecurityBlockBurst", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        m = matches[0]["match"]
        assert m.group_key == "blockburst:203.0.113.50"
        assert m.context["block_count"] == 20
        assert m.context["threshold_blocks"] == 20
        assert m.context["distinct_destination_ports"] == 20
        assert sorted(m.evidence_event_ids) == sorted(e.id for e in evs)
        assert matches[0]["rule_model"].severity == "MEDIUM"
        assert "Security block burst" in m.summary

    def test_below_threshold(self, db_session):
        insert_events(db_session, [_block(BASE + timedelta(seconds=i)) for i in range(19)])
        matches = scan(db_session, "SecurityBlockBurst", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_message_only_no_trigger(self, db_session):
        insert_events(
            db_session,
            [
                {"timestamp": BASE + timedelta(seconds=i), "source": "firewall", "level": "WARNING", "message": "blocked 203.0.113.51 connection", "raw_log": "r", "extra_data": {"source_ip": "203.0.113.51"}}
                for i in range(25)
            ],
        )
        matches = scan(db_session, "SecurityBlockBurst", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_allowed_action_no_trigger(self, db_session):
        insert_events(db_session, [_block(BASE + timedelta(seconds=i), action="allowed") for i in range(25)])
        matches = scan(db_session, "SecurityBlockBurst", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_denied_variant_counts(self, db_session):
        insert_events(db_session, [_block(BASE + timedelta(seconds=i), action="DENIED") for i in range(20)])
        matches = scan(db_session, "SecurityBlockBurst", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1

    def test_sources_separated(self, db_session):
        for i in range(12):
            insert_events(db_session, [_block(BASE + timedelta(seconds=i), ip="203.0.113.52")])
        for i in range(12):
            insert_events(db_session, [_block(BASE + timedelta(seconds=i), ip="203.0.113.53")])
        matches = scan(db_session, "SecurityBlockBurst", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_outside_window(self, db_session):
        insert_events(db_session, [_block(BASE + timedelta(seconds=i)) for i in range(20)])
        matches = scan(db_session, "SecurityBlockBurst", window_seconds=60, evaluation_time=BASE + timedelta(seconds=3600))
        assert len(matches) == 0

    def test_missing_fields_no_crash(self, db_session):
        insert_events(
            db_session,
            [
                {"timestamp": BASE, "source": "fw", "level": "WARNING", "message": "m", "raw_log": "r", "extra_data": None},
                {"timestamp": BASE, "source": "fw", "level": "WARNING", "message": "m", "raw_log": "r", "extra_data": {"action": "blocked"}},
                {"timestamp": BASE, "source": "fw", "level": "WARNING", "message": "m", "raw_log": "r", "extra_data": "oops"},
            ],
        )
        matches = scan(db_session, "SecurityBlockBurst", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_cooldown_dedup(self, db_session):
        insert_events(db_session, [_block(BASE + timedelta(seconds=i)) for i in range(20)])
        svc = DetectionService(engine=DetectionEngine())
        first = svc.run_detection(db=db_session, window_seconds=60, evaluation_time=BASE + timedelta(seconds=60), rule_names=["SecurityBlockBurst"])
        assert len(first) == 1
        second = svc.run_detection(db=db_session, window_seconds=60, evaluation_time=BASE + timedelta(seconds=61), rule_names=["SecurityBlockBurst"])
        assert len(second) == 0
