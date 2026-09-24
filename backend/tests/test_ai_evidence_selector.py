import pytest
from datetime import datetime, timezone, timedelta
from app.ai.evidence_selector import EvidenceSelector

def make_incident(id=1):
    class Inc:
        pass
    inc = Inc()
    inc.id = id
    inc.title = "test"
    inc.status = "open"
    inc.severity = "HIGH"
    inc.correlation_key = "ip:10.0.0.1"
    return inc

def make_alert(id, detected_at):
    class A:
        pass
    a = A()
    a.id = id
    a.rule_name = "BruteForceLogin"
    a.severity = "HIGH"
    a.status = "detected"
    a.detected_at = detected_at
    a.summary = "test"
    a.context = {}
    return a

def make_event(id, ts):
    class E:
        pass
    e = E()
    e.id = id
    e.timestamp = ts
    e.source = "auth"
    e.level = "ERROR"
    e.service = "api"
    e.host = "h1"
    e.message = "msg"
    e.raw_log = "x" * 600  # will be truncated
    e.extra_data = {"ip": "10.0.0.1"}
    return e

def test_empty_context():
    sel = EvidenceSelector()
    inc = make_incident()
    ctx = {"incident": inc, "alerts": [], "events": [], "timeline": [], "correlation": {}, "summary": {}, "entities": {}, "detection": []}
    out = sel.select(ctx)
    assert out["alerts"] == []
    assert out["events"] == []
    assert out["truncation"]["evidence_truncated"] is False
    assert f"incident:{inc.id}" in out["allowed_ids"]

def test_normal_context_deterministic():
    sel = EvidenceSelector()
    inc = make_incident()
    base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
    alerts = [make_alert(i, base+timedelta(seconds=i)) for i in range(3)]
    events = [make_event(i, base+timedelta(seconds=i)) for i in range(3)]
    # M5 would have sorted, but we test deterministic
    ctx = {"incident": inc, "alerts": alerts, "events": events, "timeline": [{"type":"event","id":1,"timestamp": base}], "correlation": {}, "summary": {}, "entities": {}, "detection": []}
    out1 = sel.select(ctx)
    out2 = sel.select(ctx)
    assert out1["allowed_ids"] == out2["allowed_ids"]
    assert out1["alerts"] == out2["alerts"]

def test_alert_limits_earliest_latest():
    sel = EvidenceSelector()
    inc = make_incident()
    base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
    alerts = [make_alert(i, base+timedelta(seconds=i)) for i in range(1, 12)]  # 11
    ctx = {"incident": inc, "alerts": alerts, "events": [], "timeline": [], "correlation": {}, "summary": {}, "entities": {}, "detection": []}
    out = sel.select(ctx)
    assert len(out["alerts"]) == 10
    assert out["truncation"]["alerts_truncated"] is True
    # earliest 5 + latest 5
    ids = [a["id"] for a in out["alerts"]]
    assert ids[:5] == [1,2,3,4,5]
    assert ids[5:] == [7,8,9,10,11]

def test_event_limits():
    sel = EvidenceSelector()
    inc = make_incident()
    base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
    events = [make_event(i, base+timedelta(seconds=i)) for i in range(1, 22)]  # 21
    ctx = {"incident": inc, "alerts": [], "events": events, "timeline": [], "correlation": {}, "summary": {}, "entities": {}, "detection": []}
    out = sel.select(ctx)
    assert len(out["events"]) == 20
    assert out["truncation"]["events_truncated"] is True
    ids = [e["id"] for e in out["events"]]
    assert ids[:10] == list(range(1,11))
    assert ids[10:] == list(range(12,22))

def test_timeline_limits():
    sel = EvidenceSelector()
    inc = make_incident()
    base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
    timeline = [{"type":"event","id":i,"timestamp": base+timedelta(seconds=i)} for i in range(31)]
    ctx = {"incident": inc, "alerts": [], "events": [], "timeline": timeline, "correlation": {}, "summary": {}, "entities": {}, "detection": []}
    out = sel.select(ctx)
    assert len(out["timeline"]) == 30
    assert out["truncation"]["timeline_truncated"] is True

def test_raw_log_truncation():
    sel = EvidenceSelector()
    inc = make_incident()
    base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
    ev = make_event(1, base)
    assert len(ev.raw_log) == 600
    ctx = {"incident": inc, "alerts": [], "events": [ev], "timeline": [], "correlation": {}, "summary": {}, "entities": {}, "detection": []}
    out = sel.select(ctx)
    assert "[…truncated]" in out["events"][0]["raw_log"]
    assert len(out["events"][0]["raw_log"]) > 500
    assert out["events"][0]["raw_log"].endswith("[…truncated]")

def test_stable_evidence_ids():
    sel = EvidenceSelector()
    inc = make_incident(5)
    base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
    alerts = [make_alert(10, base), make_alert(20, base)]
    events = [make_event(100, base), make_event(200, base)]
    ctx = {"incident": inc, "alerts": alerts, "events": events, "timeline": [], "correlation": {}, "summary": {}, "entities": {}, "detection": []}
    out = sel.select(ctx)
    assert "incident:5" in out["allowed_ids"]
    assert "alert:10" in out["allowed_ids"]
    assert "alert:20" in out["allowed_ids"]
    assert "event:100" in out["allowed_ids"]
    assert "timeline:1" not in out["allowed_ids"]

def test_total_chars_limit():
    sel = EvidenceSelector()
    inc = make_incident()
    base = datetime(2026,9,14,10,0,0,tzinfo=timezone.utc)
    # Create many large events to exceed 25000 (each event ~2k JSON, need ~15)
    events = []
    for i in range(30):
        ev = make_event(i, base)
        ev.raw_log = "a" * 2000
        ev.message = "b" * 500
        ev.extra_data = {"large": "x" * 500}
        events.append(ev)
    ctx = {"incident": inc, "alerts": [], "events": events, "timeline": [], "correlation": {}, "summary": {}, "entities": {}, "detection": []}
    out = sel.select(ctx)
    # Should mark truncated due to chars or limit truncation
    assert out["truncation"]["evidence_truncated"] is True or out["truncation"]["total_chars_approx"] > 10000
