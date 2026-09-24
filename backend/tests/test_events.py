"""Tests for minimal Event storage (M1 scaffolding).

Covers the guarantees from the approved plan:
- event `timestamp` (log time) vs `ingested_at` (server time) stay distinct,
- `raw_log` is stored verbatim,
- list endpoint returns newest-first.
"""

from datetime import datetime, timezone


def _sample_payload() -> dict:
    return {
        "timestamp": "2026-09-14T10:00:00Z",
        "source": "auth-service",
        "level": "ERROR",
        "service": "auth",
        "host": "web-01",
        "message": "Login failed for user jdoe",
        "raw_log": "2026-09-14T10:00:00Z ERROR auth-service login failed user=jdoe",
        "extra_data": {"user": "jdoe", "attempt": 3},
    }


def test_create_event_stores_raw_log_verbatim_and_sets_ingested_at(client) -> None:
    """POST /api/v1/events must persist all fields and server-set ingested_at."""
    payload = _sample_payload()

    response = client.post("/api/v1/events", json=payload)

    assert response.status_code == 201
    body = response.json()
    assert body["id"] > 0
    assert body["source"] == payload["source"]
    assert body["raw_log"] == payload["raw_log"]  # verbatim guarantee
    assert body["extra_data"] == payload["extra_data"]

    # Event time comes from the client; ingestion time is server-set.
    assert body["timestamp"].startswith("2026-09-14T10:00:00")
    assert "ingested_at" in body
    ingested_at = datetime.fromisoformat(body["ingested_at"])
    assert ingested_at.tzinfo is not None
    # Ingested now (2026), not backdated to event time edge cases.
    assert ingested_at >= datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_create_event_requires_raw_log_and_message(client) -> None:
    """Validation must reject payloads missing load-bearing fields."""
    payload = _sample_payload()
    del payload["raw_log"]

    response = client.post("/api/v1/events", json=payload)

    assert response.status_code == 422


def test_list_events_returns_newest_first(client) -> None:
    """GET /api/v1/events must return events ordered newest-first (paginated)."""
    first = _sample_payload()
    second = _sample_payload()
    second["message"] = "Second event"
    second["raw_log"] = "second raw line"

    client.post("/api/v1/events", json=first)
    client.post("/api/v1/events", json=second)

    response = client.get("/api/v1/events?limit=10")

    assert response.status_code == 200
    body = response.json()
    # New paginated response
    assert "items" in body
    assert body["total"] == 2
    assert len(body["items"]) == 2
    assert body["items"][0]["message"] == "Second event"
    assert body["items"][1]["message"] == first["message"]
    assert body["page"] == 1
    assert body["page_size"] == 10
