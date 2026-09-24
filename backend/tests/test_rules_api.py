"""Tests for Rules API (M3)."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import event as sa_event

from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.detection_rule import DetectionRule
from app.services.detection import ensure_default_rules
from app.detection.registry import rule_registry
from app.detection.rules.brute_force import BruteForceLoginRule
from app.detection.rules.error_spike import ErrorSpikeRule


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
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture()
def client(db_session):
    app = create_app()
    def override_get_db():
        yield db_session
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        # sync registry
        rule_registry.clear_all()
        rule_registry.register_class("threshold", BruteForceLoginRule)
        rule_registry.register_class("frequency", ErrorSpikeRule)
        for rm in db_session.execute(select(DetectionRule)).scalars().all():
            cls = rule_registry.get_class(rm.rule_type)
            if cls:
                inst = cls(config=rm.config)
                inst.name = rm.name
                rule_registry.register_instance(rm.name, inst)
        yield c
    app.dependency_overrides.clear()
    rule_registry.clear_all()


class TestRulesAPI:
    def test_list_rules(self, client):
        resp = client.get("/api/v1/rules")
        assert resp.status_code == 200
        rules = resp.json()
        # 2 original (M3) + 13 security rules (detection expansion)
        assert len(rules) == 15
        names = {r["name"] for r in rules}
        assert "BruteForceLogin" in names
        assert "ErrorSpike" in names
        assert names == {
            "BruteForceLogin",
            "ErrorSpike",
            "PortScan",
            "WebScan",
            "AuthenticationAnomaly",
            "SQLInjection",
            "XSSAttempt",
            "MalwareDetection",
            "PrivilegeEscalation",
            "SuspiciousProcess",
            "DNSAnomaly",
            "APIAbuse",
            "DataTransferAnomaly",
            "AccountTakeover",
            "SecurityBlockBurst",
        }

    def test_get_rule(self, client):
        resp = client.get("/api/v1/rules/BruteForceLogin")
        assert resp.status_code == 200
        assert resp.json()["name"] == "BruteForceLogin"
        assert resp.json()["rule_type"] == "threshold"

    def test_get_nonexistent_rule(self, client):
        resp = client.get("/api/v1/rules/NotExist")
        assert resp.status_code == 404

    def test_patch_disable_rule(self, client, db_session):
        resp = client.patch("/api/v1/rules/BruteForceLogin", json={"enabled": False})
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False
        # filter
        resp2 = client.get("/api/v1/rules?enabled=true")
        assert all(r["enabled"] for r in resp2.json())
        resp3 = client.get("/api/v1/rules?enabled=false")
        assert len(resp3.json()) == 1

    def test_disabled_rule_not_fires(self, client, db_session):
        # disable brute force
        client.patch("/api/v1/rules/BruteForceLogin", json={"enabled": False})
        # Re-sync registry to reflect disabled
        rule_registry.clear_all()
        rule_registry.register_class("threshold", BruteForceLoginRule)
        rule_registry.register_class("frequency", ErrorSpikeRule)
        for rm in db_session.execute(select(DetectionRule)).scalars().all():
            if not rm.enabled:
                continue
            cls = rule_registry.get_class(rm.rule_type)
            if cls:
                inst = cls(config=rm.config)
                inst.name = rm.name
                rule_registry.register_instance(rm.name, inst)
        from datetime import datetime, timedelta, timezone
        from app.models.event import Event
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(5):
            e = Event(timestamp=base + timedelta(seconds=i), source="auth-service", level="ERROR", message="fail", raw_log="raw", extra_data={"ip": "9.9.9.9"})
            db_session.add(e)
        db_session.commit()
        eval_time = base + timedelta(seconds=60)
        resp = client.post("/api/v1/detect", json={"window_seconds": 60, "evaluation_time": eval_time.isoformat()})
        assert resp.status_code == 200
        assert resp.json()["alerts_created"] == 0
