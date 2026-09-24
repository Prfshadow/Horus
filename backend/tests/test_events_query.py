"""Tests for M7.3 event querying — pagination, search, filters, sorting, detail."""

from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import event as sa_event

from fastapi.testclient import TestClient
from app.main import create_app
from app.db.base import Base
from app.db.session import get_db
from app.models.event import Event
from app.services.detection import ensure_default_rules
from app.detection.registry import rule_registry
from app.detection.rules.brute_force import BruteForceLoginRule
from app.detection.rules.error_spike import ErrorSpikeRule
from sqlalchemy import select as sel
from app.models.detection_rule import DetectionRule

@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    @sa_event.listens_for(engine, "connect")
    def fk_on(dbapi_conn, conn_rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    s = Session()
    ensure_default_rules(s)
    yield s
    s.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()

@pytest.fixture()
def client(db_session):
    app = create_app()
    def override():
        yield db_session
    app.dependency_overrides[get_db] = override
    with TestClient(app) as c:
        rule_registry.clear_all()
        rule_registry.register_class("threshold", BruteForceLoginRule)
        rule_registry.register_class("frequency", ErrorSpikeRule)
        for rm in db_session.execute(sel(DetectionRule)).scalars().all():
            cls = rule_registry.get_class(rm.rule_type)
            if cls:
                inst = cls(config=rm.config)
                inst.name = rm.name
                rule_registry.register_instance(rm.name, inst)
        yield c
    app.dependency_overrides.clear()
    rule_registry.clear_all()

def make_event(db_session, ts, source="auth", level="INFO", service=None, host=None, message="msg", extra=None):
    ev = Event(timestamp=ts, source=source, level=level, service=service, host=host, message=message, raw_log="raw", extra_data=extra)
    db_session.add(ev)
    db_session.commit()
    db_session.refresh(ev)
    return ev

def test_default_query(client, db_session):
    base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(3):
        make_event(db_session, base + timedelta(seconds=i))
    resp = client.get("/api/v1/events")
    assert resp.status_code == 200
    body = resp.json()
    assert body["page"] == 1
    assert body["page_size"] == 50
    assert body["total"] == 3
    assert len(body["items"]) == 3
    # Default sort timestamp desc: newest first
    assert body["items"][0]["timestamp"] > body["items"][1]["timestamp"]

def test_pagination(client, db_session):
    base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(5):
        make_event(db_session, base + timedelta(seconds=i), message=f"msg {i}")
    # page 1 size 2
    resp = client.get("/api/v1/events?page=1&page_size=2")
    assert resp.status_code == 200
    body = resp.json()
    assert body["page"] == 1
    assert body["page_size"] == 2
    assert body["total"] == 5
    assert body["total_pages"] == 3
    assert len(body["items"]) == 2
    # page 2
    resp2 = client.get("/api/v1/events?page=2&page_size=2")
    assert len(resp2.json()["items"]) == 2
    # page 3
    resp3 = client.get("/api/v1/events?page=3&page_size=2")
    assert len(resp3.json()["items"]) == 1
    # beyond total_pages
    resp4 = client.get("/api/v1/events?page=10&page_size=2")
    assert resp4.json()["items"] == []
    assert resp4.json()["page"] == 10

def test_page_size_bounds(client, db_session):
    resp = client.get("/api/v1/events?page_size=200")
    assert resp.status_code == 422  # max 100
    resp2 = client.get("/api/v1/events?page_size=0")
    assert resp2.status_code == 422
    resp3 = client.get("/api/v1/events?page=0")
    assert resp3.status_code == 422

def test_search(client, db_session):
    base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    make_event(db_session, base, source="auth-service", message="login failed")
    make_event(db_session, base + timedelta(seconds=10), source="payment", message="payment success")
    resp = client.get("/api/v1/events?search=auth")
    assert resp.status_code == 200
    assert resp.json()["total"] == 1
    assert resp.json()["items"][0]["source"] == "auth-service"
    # search in message
    resp2 = client.get("/api/v1/events?search=payment")
    assert resp2.json()["total"] == 1
    assert resp2.json()["items"][0]["source"] == "payment"

def test_level_filter(client, db_session):
    base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    make_event(db_session, base, level="ERROR")
    make_event(db_session, base + timedelta(seconds=10), level="INFO")
    resp = client.get("/api/v1/events?level=ERROR")
    assert resp.json()["total"] == 1
    assert resp.json()["items"][0]["level"] == "ERROR"

def test_source_filter(client, db_session):
    base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    make_event(db_session, base, source="src-a")
    make_event(db_session, base + timedelta(seconds=10), source="src-b")
    resp = client.get("/api/v1/events?source=src-a")
    assert resp.json()["total"] == 1
    assert resp.json()["items"][0]["source"] == "src-a"

def test_service_filter(client, db_session):
    base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    make_event(db_session, base, service="svc-a")
    make_event(db_session, base + timedelta(seconds=10), service="svc-b")
    resp = client.get("/api/v1/events?service=svc-a")
    assert resp.json()["total"] == 1
    assert resp.json()["items"][0]["service"] == "svc-a"

def test_host_filter(client, db_session):
    base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    make_event(db_session, base, host="host-a")
    make_event(db_session, base + timedelta(seconds=10), host="host-b")
    resp = client.get("/api/v1/events?host=host-a")
    assert resp.json()["total"] == 1
    assert resp.json()["items"][0]["host"] == "host-a"

def test_time_filter(client, db_session):
    base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    make_event(db_session, base, message="old")
    make_event(db_session, base + timedelta(hours=1), message="new")
    # Use params dict to ensure proper URL encoding of +00:00
    resp = client.get("/api/v1/events", params={"start_time": (base + timedelta(minutes=30)).isoformat()})
    assert resp.status_code == 200, resp.text
    assert resp.json()["total"] == 1
    assert resp.json()["items"][0]["message"] == "new"
    resp2 = client.get("/api/v1/events", params={"end_time": (base + timedelta(minutes=30)).isoformat()})
    assert resp2.json()["total"] == 1
    assert resp2.json()["items"][0]["message"] == "old"

def test_sorting(client, db_session):
    base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    make_event(db_session, base, source="b-service", message="second")
    make_event(db_session, base + timedelta(seconds=10), source="a-service", message="first")
    # sort by source asc
    resp = client.get("/api/v1/events?sort_by=source&sort_order=asc")
    assert resp.json()["items"][0]["source"] == "a-service"
    # sort by timestamp asc
    resp2 = client.get("/api/v1/events?sort_by=timestamp&sort_order=asc")
    assert resp2.json()["items"][0]["message"] == "second"  # older first
    # default desc
    resp3 = client.get("/api/v1/events?sort_by=timestamp&sort_order=desc")
    assert resp3.json()["items"][0]["message"] == "first"

def test_invalid_sort(client):
    resp = client.get("/api/v1/events?sort_by=invalid_field")
    assert resp.status_code == 422
    resp2 = client.get("/api/v1/events?sort_order=invalid")
    assert resp2.status_code == 422

def test_combined_filters(client, db_session):
    base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    make_event(db_session, base, level="ERROR", source="auth", service="svc", message="fail auth")
    make_event(db_session, base + timedelta(seconds=10), level="INFO", source="auth", service="svc", message="info")
    make_event(db_session, base + timedelta(seconds=20), level="ERROR", source="other", service="svc", message="fail other")
    resp = client.get("/api/v1/events?level=ERROR&source=auth&search=fail")
    assert resp.json()["total"] == 1
    assert resp.json()["items"][0]["source"] == "auth"

def test_empty_result(client, db_session):
    resp = client.get("/api/v1/events?level=CRITICAL&search=nonexistent")
    assert resp.status_code == 200
    assert resp.json()["total"] == 0
    assert resp.json()["items"] == []
    assert resp.json()["total_pages"] == 1

def test_deterministic_ordering(client, db_session):
    base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    # Same timestamp, different ids should be ordered by id desc when sort desc
    make_event(db_session, base, message="first")
    make_event(db_session, base, message="second")
    resp = client.get("/api/v1/events?sort_by=timestamp&sort_order=desc")
    items = resp.json()["items"]
    # Second inserted has higher id, should be first when timestamp equal and id desc
    assert items[0]["message"] == "second"
    assert items[1]["message"] == "first"

def test_get_event_detail(client, db_session):
    base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    ev = make_event(db_session, base, message="detail test", extra={"key": "value"})
    resp = client.get(f"/api/v1/events/{ev.id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == ev.id
    assert body["message"] == "detail test"
    assert body["extra_data"] == {"key": "value"}
    assert body["raw_log"] == "raw"

def test_get_event_not_found(client):
    resp = client.get("/api/v1/events/99999")
    assert resp.status_code == 404

def test_legacy_limit_still_works(client, db_session):
    base = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(3):
        make_event(db_session, base + timedelta(seconds=i))
    resp = client.get("/api/v1/events?limit=2")
    assert resp.status_code == 200
    body = resp.json()
    assert body["page_size"] == 2
    assert len(body["items"]) == 2
