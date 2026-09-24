"""Tests for PortScan, WebScan, AuthenticationAnomaly rules."""

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

BASE = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)


def _register_all(db_session):
    rule_registry.clear_all()
    rule_registry.register_class("threshold", BruteForceLoginRule)
    rule_registry.register_class("frequency", ErrorSpikeRule)
    rule_registry.register_class("port_scan", PortScanRule)
    rule_registry.register_class("web_scan", WebScanRule)
    rule_registry.register_class("authentication_anomaly", AuthenticationAnomalyRule)
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


class TestPortScan:
    def test_positive(self, db_session):
        data = [
            {
                "timestamp": BASE + timedelta(seconds=i * 5),
                "source": "fw",
                "level": "WARNING",
                "message": "conn",
                "raw_log": "raw",
                "extra_data": {"ip": "192.0.2.10", "destination_port": 20 + i},
            }
            for i in range(11)
        ]
        evs = insert_events(db_session, data)
        matches = scan(db_session, "PortScan", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        m = matches[0]["match"]
        assert m.group_key == "ip:192.0.2.10"
        assert m.context["distinct_ports"] == 11
        assert m.context["threshold_ports"] == 10
        assert m.context["rule_type"] == "port_scan"
        assert sorted(m.evidence_event_ids) == sorted(e.id for e in evs)
        assert matches[0]["rule_model"].severity == "HIGH"
        assert "Port scan pattern detected" in m.summary

    def test_below_threshold(self, db_session):
        data = [
            {
                "timestamp": BASE + timedelta(seconds=i * 5),
                "source": "fw",
                "level": "WARNING",
                "message": "conn",
                "raw_log": "raw",
                "extra_data": {"ip": "192.0.2.11", "destination_port": 80 + i},
            }
            for i in range(9)
        ]
        insert_events(db_session, data)
        matches = scan(db_session, "PortScan", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_outside_window(self, db_session):
        data = [
            {
                "timestamp": BASE + timedelta(seconds=i),
                "source": "fw",
                "level": "WARNING",
                "message": "conn",
                "raw_log": "raw",
                "extra_data": {"ip": "192.0.2.12", "destination_port": 100 + i},
            }
            for i in range(11)
        ]
        insert_events(db_session, data)
        matches = scan(db_session, "PortScan", window_seconds=60, evaluation_time=BASE + timedelta(seconds=300))
        assert len(matches) == 0

    def test_missing_fields_no_crash(self, db_session):
        insert_events(
            db_session,
            [
                {"timestamp": BASE, "source": "fw", "level": "WARNING", "message": "no extra", "raw_log": "raw", "extra_data": None},
                {"timestamp": BASE, "source": "fw", "level": "WARNING", "message": "no port", "raw_log": "raw", "extra_data": {"ip": "192.0.2.13"}},
                {"timestamp": BASE, "source": "fw", "level": "WARNING", "message": "bad port", "raw_log": "raw", "extra_data": {"ip": "192.0.2.13", "destination_port": "http"}},
                {"timestamp": BASE, "source": "fw", "level": "WARNING", "message": "bad extra", "raw_log": "raw", "extra_data": "oops"},
            ],
        )
        matches = scan(db_session, "PortScan", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_single_port_repeated_no_trigger(self, db_session):
        data = [
            {
                "timestamp": BASE + timedelta(seconds=i),
                "source": "fw",
                "level": "WARNING",
                "message": "conn",
                "raw_log": "raw",
                "extra_data": {"ip": "192.0.2.14", "destination_port": 443},
            }
            for i in range(20)
        ]
        insert_events(db_session, data)
        matches = scan(db_session, "PortScan", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_sources_separated(self, db_session):
        data = []
        for i in range(6):
            data.append(
                {"timestamp": BASE + timedelta(seconds=i), "source": "fw", "level": "WARNING", "message": "c", "raw_log": "r", "extra_data": {"ip": "192.0.2.15", "destination_port": 1000 + i}}
            )
            data.append(
                {"timestamp": BASE + timedelta(seconds=i), "source": "fw", "level": "WARNING", "message": "c", "raw_log": "r", "extra_data": {"ip": "192.0.2.16", "destination_port": 2000 + i}}
            )
        insert_events(db_session, data)
        matches = scan(db_session, "PortScan", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_boundary_inclusive(self, db_session):
        # 10 ports exactly at cutoff + 1 at eval_time => all counted (inclusive)
        data = [
            {"timestamp": BASE, "source": "fw", "level": "WARNING", "message": "c", "raw_log": "r", "extra_data": {"ip": "192.0.2.17", "destination_port": 3000 + i}}
            for i in range(10)
        ]
        data.append(
            {"timestamp": BASE + timedelta(seconds=60), "source": "fw", "level": "WARNING", "message": "c", "raw_log": "r", "extra_data": {"ip": "192.0.2.17", "destination_port": 4000}}
        )
        insert_events(db_session, data)
        matches = scan(db_session, "PortScan", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        assert matches[0]["match"].context["distinct_ports"] == 11

    def test_cooldown_dedup(self, db_session):
        data = [
            {"timestamp": BASE + timedelta(seconds=i * 5), "source": "fw", "level": "WARNING", "message": "c", "raw_log": "r", "extra_data": {"ip": "192.0.2.18", "destination_port": 5000 + i}}
            for i in range(11)
        ]
        insert_events(db_session, data)
        svc = DetectionService(engine=DetectionEngine())
        first = svc.run_detection(db=db_session, window_seconds=60, evaluation_time=BASE + timedelta(seconds=60), rule_names=["PortScan"])
        assert len(first) == 1
        second = svc.run_detection(db=db_session, window_seconds=60, evaluation_time=BASE + timedelta(seconds=61), rule_names=["PortScan"])
        assert len(second) == 0


class TestWebScan:
    PATHS = ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config", "/backup", "/login", "/api/debug"]

    def _events(self, ip, paths, base=BASE):
        return [
            {
                "timestamp": base + timedelta(seconds=i * 5),
                "source": "web",
                "level": "INFO",
                "message": f"GET {p}",
                "raw_log": "raw",
                "extra_data": {"ip": ip, "path": p, "method": "GET", "status_code": 404},
            }
            for i, p in enumerate(paths)
        ]

    def test_positive(self, db_session):
        evs = insert_events(db_session, self._events("198.51.100.7", self.PATHS))
        matches = scan(db_session, "WebScan", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        m = matches[0]["match"]
        assert m.group_key == "ip:198.51.100.7"
        assert m.context["distinct_paths"] == 8
        assert sorted(m.evidence_event_ids) == sorted(e.id for e in evs)
        assert matches[0]["rule_model"].severity == "MEDIUM"
        assert "Web scan pattern detected" in m.summary

    def test_below_threshold(self, db_session):
        insert_events(db_session, self._events("198.51.100.8", self.PATHS[:7]))
        matches = scan(db_session, "WebScan", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_benign_paths_no_trigger(self, db_session):
        benign = ["/index", "/about", "/products", "/contact", "/blog", "/faq", "/pricing", "/docs", "/help", "/status"]
        insert_events(db_session, self._events("198.51.100.9", benign))
        matches = scan(db_session, "WebScan", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_message_only_no_trigger(self, db_session):
        insert_events(
            db_session,
            [
                {"timestamp": BASE + timedelta(seconds=i), "source": "web", "level": "INFO", "message": f"visited /admin area {i}", "raw_log": "raw", "extra_data": None}
                for i in range(10)
            ],
        )
        matches = scan(db_session, "WebScan", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_query_strings_stripped(self, db_session):
        paths = [f"/admin?x={i}" for i in range(4)] + [f"/login?next={i}" for i in range(4)]
        insert_events(db_session, self._events("198.51.100.10", paths))
        matches = scan(db_session, "WebScan", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0  # only 2 distinct after stripping

    def test_outside_window(self, db_session):
        insert_events(db_session, self._events("198.51.100.11", self.PATHS))
        matches = scan(db_session, "WebScan", window_seconds=60, evaluation_time=BASE + timedelta(seconds=600))
        assert len(matches) == 0

    def test_sources_separated(self, db_session):
        insert_events(db_session, self._events("198.51.100.12", self.PATHS[:4]))
        insert_events(db_session, self._events("198.51.100.13", self.PATHS[4:]))
        matches = scan(db_session, "WebScan", window_seconds=120, evaluation_time=BASE + timedelta(seconds=120))
        assert len(matches) == 0

    def test_missing_path_no_crash(self, db_session):
        insert_events(
            db_session,
            [
                {"timestamp": BASE, "source": "web", "level": "INFO", "message": "m", "raw_log": "r", "extra_data": None},
                {"timestamp": BASE, "source": "web", "level": "INFO", "message": "m", "raw_log": "r", "extra_data": {"ip": "198.51.100.14", "path": 123}},
                {"timestamp": BASE, "source": "web", "level": "INFO", "message": "m", "raw_log": "r", "extra_data": "oops"},
            ],
        )
        matches = scan(db_session, "WebScan", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_cooldown_dedup(self, db_session):
        insert_events(db_session, self._events("198.51.100.15", self.PATHS))
        svc = DetectionService(engine=DetectionEngine())
        first = svc.run_detection(db=db_session, window_seconds=60, evaluation_time=BASE + timedelta(seconds=60), rule_names=["WebScan"])
        assert len(first) == 1
        second = svc.run_detection(db=db_session, window_seconds=60, evaluation_time=BASE + timedelta(seconds=61), rule_names=["WebScan"])
        assert len(second) == 0


class TestAuthenticationAnomaly:
    def _events(self, ip, users, base=BASE):
        return [
            {
                "timestamp": base + timedelta(seconds=i * 5),
                "source": "auth-service",
                "level": "ERROR",
                "message": "fail",
                "raw_log": "raw",
                "extra_data": {"ip": ip, "user": u},
            }
            for i, u in enumerate(users)
        ]

    def test_positive_spray(self, db_session):
        users = ["alice", "bob", "carol", "dave", "erin"]
        evs = insert_events(db_session, self._events("203.0.113.9", users))
        matches = scan(db_session, "AuthenticationAnomaly", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 1
        m = matches[0]["match"]
        assert m.group_key == "ip:203.0.113.9"
        assert m.context["distinct_accounts"] == 5
        assert sorted(m.context["accounts"]) == sorted(users)
        assert sorted(m.evidence_event_ids) == sorted(e.id for e in evs)
        assert matches[0]["rule_model"].severity == "HIGH"
        assert "Password-spraying pattern detected" in m.summary

    def test_below_threshold(self, db_session):
        insert_events(db_session, self._events("203.0.113.10", ["a", "b", "c", "d"]))
        matches = scan(db_session, "AuthenticationAnomaly", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_single_user_many_failures_no_trigger(self, db_session):
        insert_events(db_session, self._events("203.0.113.11", ["alice"] * 10))
        matches = scan(db_session, "AuthenticationAnomaly", window_seconds=120, evaluation_time=BASE + timedelta(seconds=120))
        assert len(matches) == 0

    def test_missing_user_no_crash(self, db_session):
        insert_events(
            db_session,
            [
                {"timestamp": BASE + timedelta(seconds=i), "source": "auth", "level": "ERROR", "message": "fail", "raw_log": "r", "extra_data": {"ip": "203.0.113.12"}}
                for i in range(7)
            ],
        )
        matches = scan(db_session, "AuthenticationAnomaly", window_seconds=60, evaluation_time=BASE + timedelta(seconds=60))
        assert len(matches) == 0

    def test_sources_separated(self, db_session):
        insert_events(db_session, self._events("203.0.113.13", ["a", "b", "c"]))
        insert_events(db_session, self._events("203.0.113.14", ["d", "e", "f"]))
        matches = scan(db_session, "AuthenticationAnomaly", window_seconds=120, evaluation_time=BASE + timedelta(seconds=120))
        assert len(matches) == 0

    def test_outside_window(self, db_session):
        insert_events(db_session, self._events("203.0.113.15", ["a", "b", "c", "d", "e"]))
        matches = scan(db_session, "AuthenticationAnomaly", window_seconds=60, evaluation_time=BASE + timedelta(seconds=900))
        assert len(matches) == 0

    def test_cooldown_dedup(self, db_session):
        insert_events(db_session, self._events("203.0.113.16", ["a", "b", "c", "d", "e"]))
        svc = DetectionService(engine=DetectionEngine())
        first = svc.run_detection(db=db_session, window_seconds=60, evaluation_time=BASE + timedelta(seconds=60), rule_names=["AuthenticationAnomaly"])
        assert len(first) == 1
        second = svc.run_detection(db=db_session, window_seconds=60, evaluation_time=BASE + timedelta(seconds=61), rule_names=["AuthenticationAnomaly"])
        assert len(second) == 0
