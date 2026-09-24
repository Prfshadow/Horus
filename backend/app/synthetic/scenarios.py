"""Synthetic scenario builders returning raw JSON log lines.

Each builder returns a list[str] of JSON log lines ordered by timestamp.
Timestamps are relative to ``now`` (last ~4 minutes) so default detection
windows catch them. Every line includes ``synthetic: true`` and a
``scenario`` name. Benign events are mixed in; they never carry suspicious
structured telemetry.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from typing import Optional

DOC_IPS = ["192.0.2.5", "192.0.2.10", "192.0.2.44", "198.51.100.7", "198.51.100.30", "198.51.100.40", "203.0.113.9", "203.0.113.20", "203.0.113.50", "203.0.113.99"]
USERS = ["alice", "bob", "carol", "dave", "erin", "svc-deploy"]
HOSTS = ["web-01", "web-02", "api-01", "ws-01", "srv-01"]
BENIGN_MESSAGES = [
    "Request completed",
    "Cache hit for /api/v1/health",
    "Worker heartbeat",
    "DB query finished",
    "Static asset served",
]

SUSPICIOUS_PATHS = ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config", "/backup", "/login", "/api/debug"]

SCENARIO_NAMES = [
    "authentication_attack",
    "network_reconnaissance",
    "web_application_attack",
    "malware_detection",
    "privilege_escalation",
    "data_transfer_anomaly",
    "multi_stage_incident",
]


def _line(ts: datetime, level: str, message: str, source: str, extra: Optional[dict] = None,
         host: str = "web-01", service: Optional[str] = None, scenario: str = "unknown") -> str:
    obj: dict = {
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "level": level,
        "message": message,
        "source": source,
        "service": service or source,
        "host": host,
        "synthetic": True,
        "scenario": scenario,
    }
    if extra:
        obj.update(extra)
    return json.dumps(obj)


def _benign(rng: random.Random, ts: datetime, scenario: str) -> str:
    level = "INFO" if rng.random() < 0.9 else "WARNING"
    return _line(
        ts, level, rng.choice(BENIGN_MESSAGES) + f" #{rng.randint(100, 9999)}",
        rng.choice(["api", "search", "payments"]), scenario=scenario,
        host=rng.choice(HOSTS),
    )


def _spread_times(rng: random.Random, now: datetime, count: int, span_seconds: int,
                  end_offset_seconds: int = 30) -> list[datetime]:
    """Deterministic ascending timestamps ending ``end_offset_seconds`` before now."""
    start = now - timedelta(seconds=end_offset_seconds + span_seconds)
    step = span_seconds / max(count, 1)
    times = []
    for i in range(count):
        jitter = rng.uniform(-1.5, 1.5)
        times.append(start + timedelta(seconds=i * step + jitter))
    return sorted(times)


def authentication_attack(seed: Optional[int] = None, now: Optional[datetime] = None) -> list[str]:
    rng = random.Random(seed)
    now = now or datetime.now(timezone.utc)
    ip = rng.choice(DOC_IPS)
    user = rng.choice(USERS)
    host = rng.choice(HOSTS)
    lines: list[str] = []
    for ts in _spread_times(rng, now, rng.randint(6, 9), 35, 10):
        lines.append(_line(ts, "ERROR", f"Failed password for {user} from {ip}",
                           "auth-service", {"ip": ip, "user": user}, host, "sshd", "authentication_attack"))
    for ts in _spread_times(rng, now, 25, 220, 20):
        lines.append(_benign(rng, ts, "authentication_attack"))
    return sorted(lines, key=lambda l: json.loads(l)["timestamp"])


def network_reconnaissance(seed: Optional[int] = None, now: Optional[datetime] = None) -> list[str]:
    rng = random.Random(seed)
    now = now or datetime.now(timezone.utc)
    ip = rng.choice(DOC_IPS)
    host = rng.choice(HOSTS)
    ports = rng.sample(range(20, 5000), 11)
    lines = [
        _line(ts, "WARNING", f"connection attempt to port {p}", "firewall",
              {"ip": ip, "destination_port": p}, host, "firewall", "network_reconnaissance")
        for ts, p in zip(_spread_times(rng, now, 11, 45, 8), ports)
    ]
    for ts in _spread_times(rng, now, 25, 220, 20):
        lines.append(_benign(rng, ts, "network_reconnaissance"))
    return sorted(lines, key=lambda l: json.loads(l)["timestamp"])


def web_application_attack(seed: Optional[int] = None, now: Optional[datetime] = None) -> list[str]:
    rng = random.Random(seed)
    now = now or datetime.now(timezone.utc)
    ip = rng.choice(DOC_IPS)
    host = rng.choice(HOSTS)
    lines: list[str] = []
    for ts, path in zip(_spread_times(rng, now, len(SUSPICIOUS_PATHS), 45, 8), SUSPICIOUS_PATHS):
        lines.append(_line(ts, "INFO", f"GET {path}", "web",
                           {"ip": ip, "path": path, "method": "GET", "status_code": 404},
                           host, "web", "web_application_attack"))
    ts_sqli = now - timedelta(seconds=25)
    lines.append(_line(ts_sqli, "INFO", "GET /search", "web",
                       {"ip": ip, "attack_type": "sqli", "path": "/search"}, host, "web", "web_application_attack"))
    ts_xss = now - timedelta(seconds=20)
    lines.append(_line(ts_xss, "INFO", "GET /comment", "web",
                       {"ip": ip, "attack_type": "xss", "path": "/comment"}, host, "web", "web_application_attack"))
    for ts in _spread_times(rng, now, 25, 220, 20):
        lines.append(_benign(rng, ts, "web_application_attack"))
    return sorted(lines, key=lambda l: json.loads(l)["timestamp"])


def malware_detection(seed: Optional[int] = None, now: Optional[datetime] = None) -> list[str]:
    rng = random.Random(seed)
    now = now or datetime.now(timezone.utc)
    host = rng.choice(HOSTS)
    lines = [
        _line(now - timedelta(seconds=40), "WARNING", "threat blocked", "endpoint",
              {"detection_type": "ransomware_detected", "threat_name": "BlackCat"},
              host, "endpoint", "malware_detection")
    ]
    for ts in _spread_times(rng, now, 25, 220, 20):
        lines.append(_benign(rng, ts, "malware_detection"))
    return sorted(lines, key=lambda l: json.loads(l)["timestamp"])


def privilege_escalation(seed: Optional[int] = None, now: Optional[datetime] = None) -> list[str]:
    rng = random.Random(seed)
    now = now or datetime.now(timezone.utc)
    host = rng.choice(HOSTS)
    user = rng.choice(USERS)
    lines = [
        _line(now - timedelta(seconds=40), "WARNING", "role change", "iam",
              {"old_role": "developer", "new_role": "Domain Admins", "target_user": user},
              host, "iam", "privilege_escalation")
    ]
    for ts in _spread_times(rng, now, 25, 220, 20):
        lines.append(_benign(rng, ts, "privilege_escalation"))
    return sorted(lines, key=lambda l: json.loads(l)["timestamp"])


def data_transfer_anomaly(seed: Optional[int] = None, now: Optional[datetime] = None) -> list[str]:
    rng = random.Random(seed)
    now = now or datetime.now(timezone.utc)
    ip = rng.choice(DOC_IPS)
    host = rng.choice(HOSTS)
    lines = [
        _line(now - timedelta(seconds=40), "INFO", "transfer", "firewall",
              {"bytes_sent": 200 * 1024 * 1024, "direction": "outbound",
               "destination_ip": "203.0.113.99", "ip": ip},
              host, "firewall", "data_transfer_anomaly")
    ]
    for ts in _spread_times(rng, now, 25, 220, 20):
        lines.append(_benign(rng, ts, "data_transfer_anomaly"))
    return sorted(lines, key=lambda l: json.loads(l)["timestamp"])


def multi_stage_incident(seed: Optional[int] = None, now: Optional[datetime] = None) -> list[str]:
    """Normal -> auth anomalies -> success -> privilege -> endpoint -> dns -> exfil.

    All stages share one IP and host so source_ip correlation groups them.
    """
    rng = random.Random(seed if seed is not None else 42)
    now = now or datetime.now(timezone.utc)
    ip = "203.0.113.99"
    host = "web-01"
    user = "alice"
    t0 = now - timedelta(seconds=230)
    lines: list[str] = []

    def at(offset: int) -> datetime:
        return t0 + timedelta(seconds=offset)

    # Normal activity
    for i in range(8):
        lines.append(_benign(rng, at(5 + i * 5), "multi_stage_incident"))
    # Authentication anomalies: 5 distinct users failing from same IP
    for i, u in enumerate(["alice", "bob", "carol", "dave", "erin"]):
        lines.append(_line(at(60 + i * 6), "ERROR", f"Failed password for {u} from {ip}",
                           "auth-service", {"ip": ip, "user": u}, host, "sshd", "multi_stage_incident"))
    # Successful authentication for alice (account takeover pattern needs 5 fails same user;
    # add 5 fails for alice then success)
    for i in range(5):
        lines.append(_line(at(95 + i * 6), "ERROR", "login failed",
                           "auth-service", {"user": user, "ip": ip, "action": "login_failed"},
                           host, "sshd", "multi_stage_incident"))
    lines.append(_line(at(130), "INFO", "login ok", "auth-service",
                       {"user": user, "ip": ip, "action": "login_success"}, host, "sshd", "multi_stage_incident"))
    # Privilege change
    lines.append(_line(at(145), "WARNING", "role change", "iam",
                       {"old_role": "developer", "new_role": "Domain Admins",
                        "target_user": user, "ip": ip}, host, "iam", "multi_stage_incident"))
    # Suspicious endpoint activity
    lines.append(_line(at(160), "WARNING", "process", "edr",
                       {"process": "powershell.exe", "parent_process": "winword.exe", "ip": ip},
                       host, "edr", "multi_stage_incident"))
    # DNS anomaly
    lines.append(_line(at(175), "WARNING", "bad domain", "dns",
                       {"domain": "evil.example", "verdict": "malicious", "ip": ip},
                       host, "dns", "multi_stage_incident"))
    # Significant outbound transfer
    lines.append(_line(at(190), "INFO", "transfer", "firewall",
                       {"bytes_sent": 200 * 1024 * 1024, "direction": "outbound",
                        "destination_ip": "203.0.113.99", "ip": ip},
                       host, "firewall", "multi_stage_incident"))
    # Trailing normal activity
    for i in range(8):
        lines.append(_benign(rng, at(200 + i * 3), "multi_stage_incident"))
    return sorted(lines, key=lambda l: json.loads(l)["timestamp"])


def mostly_normal(seed: Optional[int] = None, now: Optional[datetime] = None, count: int = 42) -> list[str]:
    """Benign-only batch that must not trigger alerts."""
    rng = random.Random(seed)
    now = now or datetime.now(timezone.utc)
    lines = [_benign(rng, ts, "mostly_normal") for ts in _spread_times(rng, now, count, 220, 240)]
    return sorted(lines, key=lambda l: json.loads(l)["timestamp"])


GENERATORS = {
    "authentication_attack": authentication_attack,
    "network_reconnaissance": network_reconnaissance,
    "web_application_attack": web_application_attack,
    "malware_detection": malware_detection,
    "privilege_escalation": privilege_escalation,
    "data_transfer_anomaly": data_transfer_anomaly,
    "multi_stage_incident": multi_stage_incident,
    "mostly_normal": mostly_normal,
}


def random_scenario(seed: Optional[int] = None, now: Optional[datetime] = None) -> tuple[str, list[str]]:
    """Pick a scenario at random and generate it with randomized telemetry."""
    rng = random.Random(seed)
    name = rng.choice([n for n in SCENARIO_NAMES])
    gen_seed = rng.randint(0, 2 ** 31 - 1)
    return name, GENERATORS[name](seed=gen_seed, now=now)


def generate(name: str, seed: Optional[int] = None, now: Optional[datetime] = None) -> list[str]:
    if name == "random":
        _, lines = random_scenario(seed=seed, now=now)
        return lines
    if name not in GENERATORS:
        raise ValueError(f"Unknown scenario: {name}")
    return GENERATORS[name](seed=seed, now=now)
