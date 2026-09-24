"""Tests for the health-check endpoint."""


def test_health_returns_ok_and_db_connected(client) -> None:
    """GET /api/v1/health must report app status and DB reachability."""
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] in {"ok", "degraded"}
    assert body["app"] == "Horus"
    assert "database" in body


def test_root_points_to_health_and_docs(client) -> None:
    """GET / must advertise docs and health URLs for discoverability."""
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["health"] == "/api/v1/health"
