"""Shared helpers for deterministic rules (M3)."""

import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from app.models.event import Event


def get_time_window(
    events: list[Event], window_seconds: int, evaluation_time: datetime
) -> list[Event]:
    """Return events where evaluation_time - window_seconds <= timestamp <= evaluation_time.

    Inclusive on both boundaries.
    Handles naive SQLite datetimes by assuming UTC.
    """
    if evaluation_time.tzinfo is None:
        evaluation_time = evaluation_time.replace(tzinfo=timezone.utc)
    cutoff = evaluation_time - timedelta(seconds=window_seconds)
    result = []
    for e in events:
        ts = e.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if cutoff <= ts <= evaluation_time:
            result.append(e)
    return result


def extract_json_path(event: Event, path: str) -> str | None:
    """Extract value via simple dot notation.

    Examples:
        "extra_data.ip" -> event.extra_data.get("ip")
        "source" -> event.source
        "service" -> event.service
        "host" -> event.host
        "level" -> event.level
        "extra_data.user" -> nested dict access
    """
    if not path:
        return None
    parts = path.split(".")
    # Direct column access
    if parts[0] in ("source", "service", "host", "level", "message"):
        val = getattr(event, parts[0], None)
        return str(val) if val is not None else None
    if parts[0] == "extra_data":
        data = event.extra_data or {}
        cur: Any = data
        for part in parts[1:]:
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return None
        if cur is None:
            return None
        return str(cur)
    # Unknown root
    return None


def group_events_by_path(
    events: list[Event], path: str
) -> dict[str, list[Event]]:
    """Group events by extracted path value. Events with None key are skipped."""
    groups: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        key = extract_json_path(e, path)
        if key is not None:
            groups[key].append(e)
    return dict(groups)


def extract_source_ip(event: Event) -> str | None:
    """Best-effort source IP from structured fields.

    Checks extra_data.ip then extra_data.source_ip. Returns None when
    absent/blank. Never raises on malformed extra_data.
    """
    try:
        data = event.extra_data or {}
        if not isinstance(data, dict):
            return None
        for key in ("ip", "source_ip"):
            val = data.get(key)
            if val is not None and str(val).strip():
                return str(val).strip()
    except Exception:
        return None
    return None


def parse_int(value: object) -> int | None:
    """Parse an int from int/float/numeric-string. None when not numeric."""
    try:
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str) and value.strip().lstrip("+-").isdigit():
            return int(value.strip())
    except Exception:
        return None
    return None


# Message signals for authentication failures. Used to recognize failed
# logins that real-world systems record at WARNING/CRITICAL instead of
# ERROR (e.g. `WARN auth.service Failed login attempt ...`). Both a failure
# word AND an authentication word are required, so unrelated warnings
# ("Failed to connect to database", "blocked connection", "bad domain")
# never match. INFO is deliberately excluded: INFO-level "failed login"
# lines must not count (covered by rule tests).
_AUTH_FAILURE_RE = re.compile(
    r"\b(failed|failure|failures|invalid|denied|unauthorized|unauthorised|incorrect)\b"
)
_AUTH_CONTEXT_RE = re.compile(
    r"\b(login|logon|auth|authentication|password|credential|credentials|signin|sign-in|username)\b"
)


def looks_like_auth_failure(event: Event) -> bool:
    """True when a WARNING/CRITICAL event's message describes an auth failure.

    ERROR-level events are handled by the usual level filters; this helper
    exists only to extend coverage to the levels real auth systems use.
    Underscores count as separators (logfmt-style `login_failed` reads as
    "login failed"). Never raises.
    """
    try:
        if (event.level or "").upper() not in ("WARNING", "CRITICAL"):
            return False
        message = event.message or ""
        if not isinstance(message, str):
            return False
        lowered = message.lower().replace("_", " ")
        return (
            _AUTH_FAILURE_RE.search(lowered) is not None
            and _AUTH_CONTEXT_RE.search(lowered) is not None
        )
    except Exception:
        return False


def filter_events(events: list[Event], filters: dict | None) -> list[Event]:
    """Apply simple equality filters like {"source": "auth-service", "level": "ERROR"}.

    Only supports top-level Event columns + extra_data JSON leaf equality.
    For extra_data, key should be like "extra_data.ip" or just top-level columns.
    """
    if not filters:
        return events
    result = []
    for e in events:
        ok = True
        for f_path, expected in filters.items():
            actual = extract_json_path(e, f_path) if "." in f_path else getattr(e, f_path, None)
            # For filters without dot, handle direct attribute vs extra_data fallback
            if "." not in f_path:
                # If attribute is None but extra_data has it, try extra_data
                if actual is None and e.extra_data and f_path in e.extra_data:
                    actual = str(e.extra_data.get(f_path))
                else:
                    actual = str(actual) if actual is not None else None
            if actual != str(expected):
                ok = False
                break
        if ok:
            result.append(e)
    return result
