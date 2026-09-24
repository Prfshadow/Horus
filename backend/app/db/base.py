"""SQLAlchemy declarative base (M1).

All ORM models inherit from `Base` so `create_all` / future Alembic
migrations see the full metadata in one place.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base for all HORUS models."""

    pass
