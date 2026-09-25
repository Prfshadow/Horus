"""Database engine + session management (M1).

- Engine is built from `settings.database_url` so SQLite -> PostgreSQL
  is a config change, not a code change.
- SQLite needs `check_same_thread=False` for FastAPI's threaded dev server.
  That flag is only applied to SQLite URLs (PostgreSQL unaffected).
- `get_db` is the FastAPI dependency that provides a request-scoped session.
"""

from collections.abc import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.db.base import Base

# Import models here so Base.metadata includes them for create_all and Alembic.
# noqa: F401  (imported for side effect / metadata registration)
from app.models import alert as _alert_model  # type: ignore[import-not-found]  # noqa: F401
from app.models import alert_event as _alert_event_model  # type: ignore[import-not-found]  # noqa: F401
from app.models import detection_rule as _detection_rule_model  # type: ignore[import-not-found]  # noqa: F401
from app.models import event as _event_model  # type: ignore[import-not-found]  # noqa: F401
from app.models import incident as _incident_model  # type: ignore[import-not-found]  # noqa: F401
from app.models import incident_alert as _incident_alert_model  # type: ignore[import-not-found]  # noqa: F401

connect_args = {}
engine_kwargs = {"pool_pre_ping": True}

if settings.database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
elif settings.database_url.startswith("postgresql"):
    # Disable hstore adapter (Neon doesn't have hstore extension)
    connect_args = {"options": "-c search_path=public", "use_native_hstore": False}

engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
    **engine_kwargs,
)


@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):  # type: ignore[no-untyped-def]
    """Enable SQLite foreign-key enforcement for AlertEvent relationships."""
    # Only for SQLite; PostgreSQL is unaffected.
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    except Exception:
        pass

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    """Create tables (M1 approach: no Alembic yet, see README ADR)."""
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Yield a request-scoped DB session, always closed afterwards."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_connection() -> bool:
    """Return True if a simple SELECT succeeds, else False."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
