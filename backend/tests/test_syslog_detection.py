"""End-to-end: syslog-style lines -> ingest -> BruteForceLogin alert.

Regression test for real-world auth logs recorded at WARNING level
(e.g. `WARN auth.service Failed login attempt ...`), which the stored
`level == ERROR` filter alone can never see.
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import event as sa_event

from app.db.base import Base
from app.models.detection_rule import DetectionRule
from app.normalizers.event_normalizer import EventNormalizer
from app.services.detection import DetectionService, ensure_default_rules
from app.services.ingestion import IngestionService
from app.detection.engine import DetectionEngine
from app.detection.registry import rule_registry
from app.detection.rules.brute_force import BruteForceLoginRule
from app.parsers.json_parser import JSONParser
from app.parsers.keyvalue_parser import KeyValueParser
from app.parsers.registry import parser_registry
from app.parsers.syslog_parser import SyslogParser
from app.parsers.text_parser import TextParser

# The exact shape from a real-world report: 5 WARN failed logins + a block notice.
WARN_BRUTE_FORCE_LINES = [
    "2026-09-24 13:43:27 WARN  auth.service     Failed login attempt username=admin ip=10.10.5.44",
    "2026-09-24 13:43:29 WARN  auth.service     Failed login attempt username=admin ip=10.10.5.44",
    "2026-09-24 13:43:31 WARN  auth.service     Failed login attempt username=admin ip=10.10.5.44",
    "2026-09-24 13:43:34 WARN  auth.service     Failed login attempt username=admin ip=10.10.5.44",
    "2026-09-24 13:43:36 WARN  auth.service     Failed login attempt username=admin ip=10.10.5.44",
    "2026-09-24 13:43:37 ERROR auth.service     Login temporarily blocked username=admin reason=too_many_attempts",
]


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
def pipeline():
    parser_registry.reset()
    parser_registry.register(JSONParser())
    parser_registry.register(SyslogParser())
    parser_registry.register(KeyValueParser())
    parser_registry.register(TextParser(), is_fallback=True)

    rule_registry.clear_all()
    rule_registry.register_class("threshold", BruteForceLoginRule)
    yield
    parser_registry.reset()
    rule_registry.clear_all()


class TestSyslogBruteForceEndToEnd:
    def test_warn_failed_logins_fire_brute_force(self, db_session, pipeline):
        svc = IngestionService(normalizer=EventNormalizer(default_source="test"))
        results = svc.ingest_batch(WARN_BRUTE_FORCE_LINES, db_session)
        db_session.commit()
        assert all(r.status == "stored" for r in results)

        # Sanity: the WARN lines really landed as WARNING with real timestamps.
        from app.models.event import Event

        stored = db_session.execute(select(Event).order_by(Event.id)).scalars().all()
        assert len(stored) == 6
        assert [e.level for e in stored[:5]] == ["WARNING"] * 5

        # Detection over the upload window must raise one HIGH alert.
        engine = DetectionEngine()
        for rm in db_session.execute(select(DetectionRule)).scalars().all():
            cls = rule_registry.get_class(rm.rule_type)
            if cls and rm.name == "BruteForceLogin":
                inst = cls(config=rm.config)
                inst.name = rm.name
                rule_registry.register_instance(rm.name, inst)
        det = DetectionService(engine)
        eval_time = datetime(2026, 9, 24, 13, 44, 0, tzinfo=timezone.utc)
        alerts = det.run_detection(
            db=db_session, window_seconds=3600, evaluation_time=eval_time,
            rule_names=["BruteForceLogin"],
        )
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.rule_name == "BruteForceLogin"
        assert alert.severity == "HIGH"
        assert "5 failed logins" in alert.summary
        from app.models.alert_event import AlertEvent

        linked = db_session.execute(
            select(AlertEvent.event_id).where(AlertEvent.alert_id == alert.id)
        ).scalars().all()
        assert len(linked) == 5
