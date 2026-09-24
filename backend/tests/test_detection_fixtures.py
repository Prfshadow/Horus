"""Fixture smoke coverage: every synthetic fixture fires exactly its rule.

Uses rule_names-filtered scans so cross-rule firing cannot pollute
assertions. Fixture data lives in tests/fixtures/synthetic_security_events.
"""

from datetime import timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import event as sa_event

from app.db.base import Base
from app.models.event import Event
from app.models.detection_rule import DetectionRule
from app.services.detection import ensure_default_rules
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
from tests.fixtures import synthetic_security_events as fx

BASE = fx.BASE


def _register_all(db_session):
    rule_registry.clear_all()
    for rule_type, cls in [
        ("threshold", BruteForceLoginRule),
        ("frequency", ErrorSpikeRule),
        ("port_scan", PortScanRule),
        ("web_scan", WebScanRule),
        ("authentication_anomaly", AuthenticationAnomalyRule),
        ("sql_injection", SQLInjectionRule),
        ("xss_attempt", XSSAttemptRule),
        ("malware_detection", MalwareDetectionRule),
        ("privilege_escalation", PrivilegeEscalationRule),
        ("suspicious_process", SuspiciousProcessRule),
        ("dns_anomaly", DNSAnomalyRule),
        ("api_abuse", APIAbuseRule),
        ("data_transfer_anomaly", DataTransferAnomalyRule),
        ("account_takeover", AccountTakeoverRule),
        ("security_block_burst", SecurityBlockBurstRule),
    ]:
        rule_registry.register_class(rule_type, cls)
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


def _fire(db_session, rule_name, data, window=120):
    # All fixtures place events within [BASE, BASE+60s]; evaluating at
    # BASE+60s keeps every event inside each rule's own config window.
    for d in data:
        db_session.add(Event(**d))
    db_session.commit()
    eval_time = BASE + timedelta(seconds=60)
    engine = DetectionEngine()
    results = engine.scan_recent(db=db_session, window_seconds=window, evaluation_time=eval_time, rule_names=[rule_name])
    matched = [r for r in results if r["rule_model"].name == rule_name]
    assert len(matched) == 1
    assert matched[0]["match"].evidence_event_ids
    return matched[0]


class TestSyntheticFixtures:
    def test_brute_force(self, db_session):
        _fire(db_session, "BruteForceLogin", fx.brute_force_events())

    def test_error_spike(self, db_session):
        # Default ErrorSpike needs 100 events/300s for 20/min; use a
        # relaxed config here (mirrors test_detection_api.py).
        rule = db_session.execute(select(DetectionRule).where(DetectionRule.name == "ErrorSpike")).scalars().first()
        rule.config = {"min_events": 5, "window_seconds": 60, "rate_threshold": 5, "group_by": "service", "filter": {"level": "ERROR"}}
        db_session.commit()
        _register_all(db_session)
        _fire(db_session, "ErrorSpike", fx.error_spike_events(), window=60)

    def test_port_scan(self, db_session):
        _fire(db_session, "PortScan", fx.port_scan_events())

    def test_web_scan(self, db_session):
        _fire(db_session, "WebScan", fx.web_scan_events())

    def test_authentication_anomaly(self, db_session):
        _fire(db_session, "AuthenticationAnomaly", fx.authentication_anomaly_events())

    def test_sql_injection(self, db_session):
        _fire(db_session, "SQLInjection", fx.sql_injection_events())

    def test_xss_attempt(self, db_session):
        _fire(db_session, "XSSAttempt", fx.xss_attempt_events())

    def test_malware_detection(self, db_session):
        _fire(db_session, "MalwareDetection", fx.malware_events())

    def test_privilege_escalation(self, db_session):
        _fire(db_session, "PrivilegeEscalation", fx.privilege_escalation_events())

    def test_suspicious_process(self, db_session):
        _fire(db_session, "SuspiciousProcess", fx.suspicious_process_events())

    def test_dns_anomaly(self, db_session):
        _fire(db_session, "DNSAnomaly", fx.dns_anomaly_events())

    def test_api_abuse(self, db_session):
        _fire(db_session, "APIAbuse", fx.api_abuse_events())

    def test_data_transfer_anomaly(self, db_session):
        _fire(db_session, "DataTransferAnomaly", fx.data_transfer_events())

    def test_account_takeover(self, db_session):
        _fire(db_session, "AccountTakeover", fx.account_takeover_events())

    def test_security_block_burst(self, db_session):
        _fire(db_session, "SecurityBlockBurst", fx.block_burst_events())
