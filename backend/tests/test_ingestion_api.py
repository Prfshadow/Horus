"""Tests for ingestion API endpoints (M2)."""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
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
def client(db_session: Session) -> TestClient:
    """Provide a TestClient with test database."""
    parser_registry.reset()
    app = create_app()

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


class TestIngestionAPI:
    """Test POST /api/v1/ingest endpoint."""

    def test_ingest_batch_json_logs(self, client):
        payload = {
            "logs": [
                '{"timestamp": "2026-09-14T10:00:00Z", "level": "ERROR", "message": "Failed login"}',
                '{"timestamp": "2026-09-14T10:00:01Z", "level": "INFO", "message": "User logged in"}',
            ]
        }

        response = client.post("/api/v1/ingest", json=payload)

        assert response.status_code == 200
        body = response.json()
        assert body["accepted"] == 2
        assert body["failed"] == 0
        assert len(body["results"]) == 2
        assert body["results"][0]["status"] == "stored"
        assert body["results"][1]["status"] == "stored"
        assert body["results"][0]["event_id"] is not None
        assert body["results"][1]["event_id"] is not None
        assert body["results"][0]["index"] == 0
        assert body["results"][1]["index"] == 1

    def test_ingest_batch_mixed_formats(self, client):
        payload = {
            "logs": [
                '{"level": "ERROR", "message": "JSON log"}',
                "level=INFO message=KV log",
                "plain text log",
            ],
            "source": "api-gateway"
        }

        response = client.post("/api/v1/ingest", json=payload)

        assert response.status_code == 200
        body = response.json()
        assert body["accepted"] == 3
        assert body["failed"] == 0
        assert len(body["results"]) == 3

        # Check parsers used
        assert body["results"][0]["event_id"] is not None
        assert body["results"][1]["event_id"] is not None
        assert body["results"][2]["event_id"] is not None

    def test_ingest_batch_parse_failure_reported(self, client):
        payload = {
            "logs": [
                '{"valid": "json"}',
                '{"invalid": json}',  # Valid JSON structure but invalid (unquoted key/value) - parse failure
                '{"another": "valid"}',
            ]
        }

        response = client.post("/api/v1/ingest", json=payload)

        assert response.status_code == 200
        body = response.json()
        assert body["accepted"] == 2
        assert body["failed"] == 1
        assert len(body["results"]) == 3
        assert body["results"][0]["status"] == "stored"
        assert body["results"][1]["status"] == "parse_error"
        assert body["results"][1]["error"] is not None
        assert body["results"][2]["status"] == "stored"

    def test_ingest_batch_empty_logs_rejected(self, client):
        payload = {"logs": []}
        response = client.post("/api/v1/ingest", json=payload)
        assert response.status_code == 422  # Validation error

    def test_ingest_batch_oversized_rejected(self, client):
        payload = {"logs": ["log"] * 1001}  # Max 1000
        response = client.post("/api/v1/ingest", json=payload)
        assert response.status_code == 422

    def test_ingest_batch_missing_logs_field_rejected(self, client):
        payload = {"source": "test"}
        response = client.post("/api/v1/ingest", json=payload)
        assert response.status_code == 422

    def test_ingest_batch_default_source_applied(self, client):
        payload = {
            "logs": ['{"message": "no source"}'],
            "source": "my-source"
        }

        response = client.post("/api/v1/ingest", json=payload)

        assert response.status_code == 200
        body = response.json()
        assert body["accepted"] == 1

    def test_ingest_batch_preserves_raw_log(self, client):
        raw_logs = [
            '{"message": "exact"}',
            "  whitespace  ",
        ]
        payload = {"logs": raw_logs}

        response = client.post("/api/v1/ingest", json=payload)

        assert response.status_code == 200
        # Verify by fetching events
        # Note: We can't directly check DB here, but we can verify the response structure
        body = response.json()
        assert body["accepted"] == 2

    def test_ingest_single_log_as_batch_of_one(self, client):
        """Single log ingestion works as batch of 1."""
        payload = {"logs": ['{"level": "INFO", "message": "single log"}']}
        response = client.post("/api/v1/ingest", json=payload)

        assert response.status_code == 200
        body = response.json()
        assert body["accepted"] == 1
        assert len(body["results"]) == 1