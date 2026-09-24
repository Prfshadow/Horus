"""Shared pytest fixtures (M1+M2+M3).

Each test gets an isolated in-memory SQLite database so tests never
touch the dev `horus.db` file and never interfere with each other.
"""

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import event as sa_event
from sqlalchemy.engine import Engine

from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.parsers.registry import parser_registry
from app.detection.registry import rule_registry
from app.models.detection_rule import DetectionRule
from app.services.detection import ensure_default_rules
from app.detection.rules.brute_force import BruteForceLoginRule
from app.detection.rules.error_spike import ErrorSpikeRule


@pytest.fixture()
def db_session() -> Generator[Session, None, None]:
    """Provide a fresh in-memory DB session with all tables created."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    # Enable FK for SQLite in-memory
    @sa_event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, conn_rec):  # type: ignore[no-untyped-def]
        try:
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()
        except Exception:
            pass

    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    session = TestingSession()
    # Seed default detection rules for M3
    ensure_default_rules(session)
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture()
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Provide a TestClient whose `get_db` dependency uses the test session."""
    app = create_app()

    def override_get_db() -> Generator[Session, None, None]:
        try:
            yield db_session
        finally:
            pass  # session lifecycle is managed by `db_session` fixture

    app.dependency_overrides[get_db] = override_get_db

    # `with` block ensures lifespan startup/shutdown runs cleanly.
    with TestClient(app) as test_client:
        # Lifespan has run with file DB; re-sync registries to test DB
        rule_registry.clear_all()
        rule_registry.register_class("threshold", BruteForceLoginRule)
        rule_registry.register_class("frequency", ErrorSpikeRule)
        for rm in db_session.execute(select(DetectionRule)).scalars().all():
            cls = rule_registry.get_class(rm.rule_type)
            if cls:
                inst = cls(config=rm.config)
                inst.name = rm.name
                rule_registry.register_instance(rm.name, inst)
        yield test_client

    app.dependency_overrides.clear()
    # Clean up registries
    parser_registry.reset()
    rule_registry.clear_all()
