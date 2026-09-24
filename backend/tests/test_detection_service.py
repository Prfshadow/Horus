"""Tests for DetectionService (M3)."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import event as sa_event

from app.db.base import Base
from app.models.event import Event
from app.models.alert import Alert
from app.models.alert_event import AlertEvent
from app.models.detection_rule import DetectionRule
from app.detection.engine import DetectionEngine
from app.detection.registry import rule_registry
from app.detection.rules.brute_force import BruteForceLoginRule
from app.detection.rules.error_spike import ErrorSpikeRule
from app.services.detection import DetectionService, ensure_default_rules


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
    rule_registry.clear_all()
    rule_registry.register_class("threshold", BruteForceLoginRule)
    rule_registry.register_class("frequency", ErrorSpikeRule)
    for rm in session.execute(select(DetectionRule)).scalars().all():
        cls = rule_registry.get_class(rm.rule_type)
        if cls:
            inst = cls(config=rm.config)
            inst.name = rm.name
            rule_registry.register_instance(rm.name, inst)
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
        rule_registry.clear_all()


def insert_events(db: Session, data: list[dict]) -> list[Event]:
    evs = []
    for d in data:
        e = Event(**d)
        db.add(e)
        evs.append(e)
    db.commit()
    for e in evs:
        db.refresh(e)
    return evs


class TestDetectionService:
    def test_run_detection_creates_alert(self, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        eval_time = base + timedelta(seconds=60)
        data = [
            {"timestamp": base + timedelta(seconds=i), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.5"}}
            for i in range(5)
        ]
        insert_events(db_session, data)
        svc = DetectionService(engine=DetectionEngine())
        alerts = svc.run_detection(db=db_session, window_seconds=60, evaluation_time=eval_time)
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.rule_name == "BruteForceLogin"
        assert alert.status == "detected"
        assert alert.context["group_key"] == "10.0.0.5"
        # Check AlertEvent links
        links = db_session.execute(select(AlertEvent).where(AlertEvent.alert_id == alert.id)).scalars().all()
        assert len(links) == 5

    def test_cooldown_prevents_duplicate(self, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        eval_time = base + timedelta(seconds=60)
        data = [
            {"timestamp": base + timedelta(seconds=i), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.5"}}
            for i in range(5)
        ]
        insert_events(db_session, data)
        svc = DetectionService(engine=DetectionEngine())
        alerts1 = svc.run_detection(db=db_session, window_seconds=60, evaluation_time=eval_time)
        assert len(alerts1) == 1
        # Immediate second run within cooldown -> no new alert
        alerts2 = svc.run_detection(db=db_session, window_seconds=60, evaluation_time=eval_time)
        assert len(alerts2) == 0
        # Total still 1
        all_alerts = db_session.execute(select(Alert)).scalars().all()
        assert len(all_alerts) == 1

    def test_cooldown_expired_allows_new(self, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        eval_time1 = base + timedelta(seconds=60)
        data = [
            {"timestamp": base + timedelta(seconds=i), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.5"}}
            for i in range(5)
        ]
        insert_events(db_session, data)
        svc = DetectionService(engine=DetectionEngine())
        alerts1 = svc.run_detection(db=db_session, window_seconds=60, evaluation_time=eval_time1)
        assert len(alerts1) == 1
        # Resolve first alert
        alerts1[0].status = "resolved"
        db_session.commit()
        # Eval after cooldown (300s) + new events
        eval_time2 = base + timedelta(seconds=400)
        # Need new events in new window
        data2 = [
            {"timestamp": eval_time2 - timedelta(seconds=10 - i), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": "raw", "extra_data": {"ip": "10.0.0.5"}}
            for i in range(5)
        ]
        insert_events(db_session, data2)
        alerts2 = svc.run_detection(db=db_session, window_seconds=60, evaluation_time=eval_time2)
        assert len(alerts2) == 1

    def test_evidence_links(self, db_session):
        base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        eval_time = base + timedelta(seconds=60)
        data = [
            {"timestamp": base + timedelta(seconds=i), "source": "auth-service", "level": "ERROR", "message": "fail", "raw_log": f"raw{i}", "extra_data": {"ip": "9.9.9.9"}}
            for i in range(5)
        ]
        evs = insert_events(db_session, data)
        svc = DetectionService(engine=DetectionEngine())
        alerts = svc.run_detection(db=db_session, window_seconds=60, evaluation_time=eval_time)
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.first_event_id == min(e.id for e in evs)
        assert alert.last_event_id == max(e.id for e in evs)
        links = db_session.execute(select(AlertEvent).where(AlertEvent.alert_id == alert.id)).scalars().all()
        assert sorted([l.event_id for l in links]) == sorted([e.id for e in evs])
