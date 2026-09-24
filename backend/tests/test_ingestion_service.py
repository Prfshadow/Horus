"""Tests for IngestionService (M2)."""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.event import Event
from app.normalizers.event_normalizer import EventNormalizer
from app.services.ingestion import IngestionService
from app.parsers.json_parser import JSONParser
from app.parsers.keyvalue_parser import KeyValueParser
from app.parsers.text_parser import TextParser
from app.parsers.registry import parser_registry


@pytest.fixture()
def db_session() -> Session:
    """Provide a fresh in-memory DB session."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    session = TestingSession()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture()
def ingestion_service() -> IngestionService:
    # Register parsers in the global registry
    parser_registry.reset()
    parser_registry.register(JSONParser())
    parser_registry.register(KeyValueParser())
    parser_registry.register(TextParser(), is_fallback=True)
    return IngestionService(normalizer=EventNormalizer(default_source="test-source"))


class TestIngestionService:
    """Test IngestionService.ingest_batch."""

    def test_ingest_batch_json_logs(self, db_session, ingestion_service):
        raw_logs = [
            '{"timestamp": "2026-09-14T10:00:00Z", "level": "ERROR", "message": "Failed login", "service": "auth"}',
            '{"timestamp": "2026-09-14T10:00:01Z", "level": "INFO", "message": "User logged in", "service": "auth"}',
        ]

        results = ingestion_service.ingest_batch(raw_logs, db_session)

        assert len(results) == 2
        assert results[0].status == "stored"
        assert results[0].event_id is not None
        assert results[1].status == "stored"
        assert results[1].event_id is not None

        # Verify in database
        events = db_session.query(Event).order_by(Event.id).all()
        assert len(events) == 2
        assert events[0].level == "ERROR"
        assert events[1].level == "INFO"
        assert events[0].raw_log == raw_logs[0]
        assert events[1].raw_log == raw_logs[1]

    def test_ingest_batch_mixed_formats(self, db_session, ingestion_service):
        raw_logs = [
            '{"timestamp": "2026-09-14T10:00:00Z", "level": "ERROR", "message": "JSON log"}',
            "timestamp=2026-09-14T10:00:01Z level=INFO message=KV log",
            "plain text log line",
        ]

        results = ingestion_service.ingest_batch(raw_logs, db_session)

        assert len(results) == 3
        assert all(r.status == "stored" for r in results)

        events = db_session.query(Event).order_by(Event.id).all()
        assert len(events) == 3
        assert events[0].extra_data["parser"] == "json"
        assert events[1].extra_data["parser"] == "keyvalue"
        assert events[2].extra_data["parser"] == "text"
        assert events[2].extra_data["parse_status"] == "fallback"

    def test_ingest_batch_parse_failure_continues(self, db_session, ingestion_service):
        raw_logs = [
            '{"valid": "json"}',
            '{"invalid": json}',  # Valid JSON structure but invalid (unquoted key/value) - parse failure
            '{"another": "valid"}',
        ]

        results = ingestion_service.ingest_batch(raw_logs, db_session)

        assert len(results) == 3
        assert results[0].status == "stored"
        assert results[1].status == "parse_error"
        assert results[1].error is not None
        assert results[2].status == "stored"

        # All three events stored (parse failures stored as ERROR events)
        events = db_session.query(Event).order_by(Event.id).all()
        assert len(events) == 3
        assert events[0].level == "INFO"
        assert events[1].level == "ERROR"  # Parse failure = ERROR
        assert events[2].level == "INFO"
        assert "parse_error" in events[1].extra_data

    def test_ingest_batch_default_source_used(self, db_session, ingestion_service):
        raw_logs = ['{"message": "no source in json"}']

        results = ingestion_service.ingest_batch(raw_logs, db_session, default_source="my-api")

        assert results[0].status == "stored"
        event = db_session.query(Event).first()
        assert event.source == "my-api"

    def test_ingest_batch_parsed_source_overrides_default(self, db_session, ingestion_service):
        raw_logs = ['{"source": "parsed-source", "message": "has source"}']

        results = ingestion_service.ingest_batch(raw_logs, db_session, default_source="default-source")

        assert results[0].status == "stored"
        event = db_session.query(Event).first()
        assert event.source == "parsed-source"

    def test_ingest_batch_preserves_raw_log_exactly(self, db_session, ingestion_service):
        raw_logs = [
            '{"message": "exact preservation"}',
            "  whitespace  ",
            "unicode: café 🚀",
        ]

        results = ingestion_service.ingest_batch(raw_logs, db_session)

        events = db_session.query(Event).order_by(Event.id).all()
        for i, event in enumerate(events):
            assert event.raw_log == raw_logs[i]

    def test_ingest_batch_empty_list(self, db_session, ingestion_service):
        results = ingestion_service.ingest_batch([], db_session)
        assert results == []

    def test_ingest_batch_timestamp_fallback(self, db_session, ingestion_service):
        # Log without timestamp
        raw_logs = ['{"message": "no timestamp"}']

        results = ingestion_service.ingest_batch(raw_logs, db_session)

        event = db_session.query(Event).first()
        # Should fall back to ingestion time (within a few seconds)
        # SQLite returns naive datetime, normalize for comparison
        event_ts = event.timestamp
        if event_ts.tzinfo is None:
            event_ts = event_ts.replace(tzinfo=timezone.utc)
        ingestion_time = datetime.now(timezone.utc)
        assert abs((event_ts - ingestion_time).total_seconds()) < 5
        assert event.extra_data["timestamp_source"] == "ingestion_fallback"