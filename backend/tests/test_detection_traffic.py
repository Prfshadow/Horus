"""Tests for DNSAnomaly and APIAbuse rules."""

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


class TestDNSAnomaly:
    def _dns(self, host, domains, base=BASE, step=2):
        return [
            {
                "timestamp": base + timedelta(seconds=i * step),
                "source": "dns",
                "level": "INFO",
                "message": f"query {d}",
                "raw_log": "raw",
                "extra_data": {"domain": d},
                "host": host,
            }
            for i, d in enumerate(domains)
        ]

    def test_verdict_malicious(self, db_session):
        evs = insert_events(
            db_session,
            [
                {
                    "timestamp": BASE,
                    "source": "dns",
                    "level": "WARNING",
                    "message": "bad domain",
                    "raw_log": "raw",
                    "extra_data": {"domain": "evil.example", "verdict": "malicious"},
                    "host": "ws-01",
                }
            ],
        )
        matches = scan(db_session, "DNSAnomaly", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        m = matches[0]["match"]
        assert m.context["rule_type"] == "dns_anomaly"
        assert m.context["domain"] == "evil.example"
        assert sorted(m.evidence_event_ids) == sorted(e.id for e in evs)
        assert matches[0]["rule_model"].severity == "MEDIUM"
        assert "Suspicious DNS verdict" in m.summary

    def test_verdict_case_insensitive(self, db_session):
        insert_events(
            db_session,
            [
                {
                    "timestamp": BASE,
                    "source": "dns",
                    "level": "WARNING",
                    "message": "dga?",
                    "raw_log": "raw",
                    "extra_data": {"query": "xj29qz.example", "verdict": "DGA"},
                    "host": "ws-02",
                }
            ],
        )
        matches = scan(db_session, "DNSAnomaly", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1

    def test_benign_verdict_no_trigger(self, db_session):
        insert_events(
            db_session,
            [
                {
                    "timestamp": BASE,
                    "source": "dns",
                    "level": "INFO",
                    "message": "ok",
                    "raw_log": "raw",
                    "extra_data": {"domain": "example.com", "verdict": "clean"},
                    "host": "ws-03",
                }
            ],
        )
        matches = scan(db_session, "DNSAnomaly", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_behavioral_many_unique_domains(self, db_session):
        domains = [f"host{i:04d}.example" for i in range(55)]
        evs = insert_events(db_session, self._dns("ws-04", domains))
        matches = scan(db_session, "DNSAnomaly", window_seconds=300, evaluation_time=BASE + timedelta(seconds=300))
        assert len(matches) == 1
        m = matches[0]["match"]
        assert m.group_key == "dns:ws-04"
        assert m.context["distinct_domains"] == 55
        assert sorted(m.evidence_event_ids) == sorted(e.id for e in evs)

    def test_repeated_same_domain_no_trigger(self, db_session):
        insert_events(db_session, self._dns("ws-05", ["example.com"] * 200))
        matches = scan(db_session, "DNSAnomaly", window_seconds=300, evaluation_time=BASE + timedelta(seconds=400))
        assert len(matches) == 0

    def test_below_threshold(self, db_session):
        insert_events(db_session, self._dns("ws-06", [f"d{i}.example" for i in range(49)]))
        matches = scan(db_session, "DNSAnomaly", window_seconds=300, evaluation_time=BASE + timedelta(seconds=300))
        assert len(matches) == 0

    def test_outside_window(self, db_session):
        insert_events(db_session, self._dns("ws-07", [f"q{i}.example" for i in range(55)], base=BASE))
        matches = scan(db_session, "DNSAnomaly", window_seconds=60, evaluation_time=BASE + timedelta(seconds=3600))
        assert len(matches) == 0

    def test_missing_fields_no_crash(self, db_session):
        insert_events(
            db_session,
            [
                {"timestamp": BASE, "source": "dns", "level": "INFO", "message": "m", "raw_log": "r", "extra_data": None},
                {"timestamp": BASE, "source": "dns", "level": "INFO", "message": "m", "raw_log": "r", "extra_data": {"verdict": "malicious"}},
                {"timestamp": BASE, "source": "dns", "level": "INFO", "message": "m", "raw_log": "r", "extra_data": "oops"},
            ],
        )
        matches = scan(db_session, "DNSAnomaly", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_cooldown_dedup(self, db_session):
        insert_events(
            db_session,
            [
                {
                    "timestamp": BASE,
                    "source": "dns",
                    "level": "WARNING",
                    "message": "bad",
                    "raw_log": "raw",
                    "extra_data": {"domain": "evil2.example", "verdict": "c2"},
                    "host": "ws-08",
                }
            ],
        )
        svc = DetectionService(engine=DetectionEngine())
        first = svc.run_detection(db=db_session, window_seconds=300, evaluation_time=BASE + timedelta(seconds=60), rule_names=["DNSAnomaly"])
        assert len(first) == 1
        second = svc.run_detection(db=db_session, window_seconds=300, evaluation_time=BASE + timedelta(seconds=61), rule_names=["DNSAnomaly"])
        assert len(second) == 0


class TestAPIAbuse:
    def _api(self, ip, n, base=BASE, step=0, service="api"):
        return [
            {
                "timestamp": base + timedelta(seconds=i * step),
                "source": service,
                "level": "INFO",
                "message": f"GET /v1/items/{i}",
                "raw_log": "raw",
                "extra_data": {"ip": ip, "endpoint": f"/v1/items/{i % 10}", "method": "GET", "status_code": 200},
            }
            for i in range(n)
        ]

    def test_positive(self, db_session):
        evs = insert_events(db_session, self._api("198.51.100.40", 110, step=0))
        matches = scan(db_session, "APIAbuse", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        m = matches[0]["match"]
        assert m.group_key == "ip:198.51.100.40"
        assert m.context["request_count"] == 110
        assert m.context["threshold_requests"] == 100
        assert sorted(m.evidence_event_ids) == sorted(e.id for e in evs)
        assert matches[0]["rule_model"].severity == "MEDIUM"
        assert "API abuse pattern detected" in m.summary

    def test_below_threshold(self, db_session):
        insert_events(db_session, self._api("198.51.100.41", 99, step=0))
        matches = scan(db_session, "APIAbuse", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_non_api_volume_no_trigger(self, db_session):
        insert_events(
            db_session,
            [
                {"timestamp": BASE + timedelta(seconds=i), "source": "app", "level": "INFO", "message": f"heartbeat {i}", "raw_log": "raw", "extra_data": {"ip": "198.51.100.42"}}
                for i in range(150)
            ],
        )
        matches = scan(db_session, "APIAbuse", window_seconds=300, evaluation_time=BASE + timedelta(seconds=300))
        assert len(matches) == 0

    def test_missing_ip_no_trigger(self, db_session):
        insert_events(
            db_session,
            [
                {"timestamp": BASE, "source": "api", "level": "INFO", "message": "m", "raw_log": "r", "extra_data": {"endpoint": "/v1/x", "method": "GET", "status_code": 200}}
                for _ in range(120)
            ],
        )
        matches = scan(db_session, "APIAbuse", window_seconds=300, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_rate_limited_counted(self, db_session):
        data = self._api("198.51.100.43", 110, step=0)
        for d in data[:10]:
            d["extra_data"] = {**d["extra_data"], "rate_limited": True}
        insert_events(db_session, data)
        matches = scan(db_session, "APIAbuse", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        assert matches[0]["match"].context["rate_limited_count"] == 10

    def test_outside_window(self, db_session):
        insert_events(db_session, self._api("198.51.100.44", 110, step=0))
        matches = scan(db_session, "APIAbuse", window_seconds=60, evaluation_time=BASE + timedelta(seconds=3600))
        assert len(matches) == 0

    def test_sources_separated(self, db_session):
        insert_events(db_session, self._api("198.51.100.45", 60, step=0))
        insert_events(db_session, self._api("198.51.100.46", 60, step=0))
        matches = scan(db_session, "APIAbuse", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_cooldown_dedup(self, db_session):
        insert_events(db_session, self._api("198.51.100.47", 110, step=0))
        svc = DetectionService(engine=DetectionEngine())
        first = svc.run_detection(db=db_session, window_seconds=60, evaluation_time=BASE + timedelta(seconds=60), rule_names=["APIAbuse"])
        assert len(first) == 1
        second = svc.run_detection(db=db_session, window_seconds=60, evaluation_time=BASE + timedelta(seconds=61), rule_names=["APIAbuse"])
        assert len(second) == 0
