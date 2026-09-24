"""Health-check endpoint (M1).

Proves the app boots and can reach the database.
Used by developers, tests, and (later) container orchestration.
"""

from fastapi import APIRouter

from app.core.config import settings
from app.db.session import check_connection

router = APIRouter(tags=["health"])


@router.get("/health")
def health_check() -> dict:
    """Return app status plus database reachability."""
    db_ok = check_connection()
    return {
        "status": "ok" if db_ok else "degraded",
        "app": settings.app_name,
        "env": settings.app_env,
        "database": "connected" if db_ok else "unreachable",
    }
