"""Deterministic SYNTHETIC fixtures for detection-rule demos and tests.

All IPs use documentation ranges (TEST-NET-1/2/3: 192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24). No real user data. Each builder returns
a list of event dicts ready for ``Event(**d)`` that triggers exactly one
rule when evaluated with the documented window/evaluation time.
"""

from datetime import datetime, timedelta, timezone

BASE = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)


def _base(ts, source, level, message, extra=None, host=None, service=None):
    return {
        "timestamp": ts,
        "source": source,
        "level": level,
        "message": message,
        "raw_log": "synthetic fixture",
        "extra_data": extra,
        "host": host,
        "service": service,
    }


def brute_force_events(n=5, ip="192.0.2.5"):
    return [
        _base(BASE + timedelta(seconds=i), "auth-service", "ERROR", "fail", {"ip": ip})
        for i in range(n)
    ]


def error_spike_events(n=6, service="payments"):
    # Pairs with a relaxed test-only config; see fixture test.
    return [
        _base(BASE + timedelta(seconds=i * 5), "app", "ERROR", "err", {}, host="h1", service=service)
        for i in range(n)
    ]


def port_scan_events(n=11, ip="192.0.2.10"):
    return [
        _base(BASE + timedelta(seconds=i * 5), "fw", "WARNING", "conn",
              {"ip": ip, "destination_port": 20 + i})
        for i in range(n)
    ]


def web_scan_events(ip="198.51.100.7"):
    paths = ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config", "/backup", "/login", "/api/debug"]
    return [
        _base(BASE + timedelta(seconds=i * 5), "web", "INFO", f"GET {p}",
              {"ip": ip, "path": p, "method": "GET", "status_code": 404})
        for i, p in enumerate(paths)
    ]


def authentication_anomaly_events(ip="203.0.113.9"):
    users = ["alice", "bob", "carol", "dave", "erin"]
    return [
        _base(BASE + timedelta(seconds=i * 5), "auth-service", "ERROR", "fail",
              {"ip": ip, "user": u})
        for i, u in enumerate(users)
    ]


def sql_injection_events(ip="203.0.113.20"):
    return [
        _base(BASE, "web", "INFO", "GET /search", {
            "ip": ip, "attack_type": "sqli", "path": "/search",
            "payload": "q=1 UNION SELECT password FROM users",
        })
    ]


def xss_attempt_events(ip="198.51.100.30"):
    return [
        _base(BASE, "web", "INFO", "GET /comment", {
            "ip": ip, "attack_type": "xss", "payload": "<script>alert(document.cookie)</script>",
        })
    ]


def malware_events():
    return [
        _base(BASE, "endpoint", "WARNING", "threat blocked", {
            "detection_type": "ransomware_detected", "threat_name": "BlackCat",
        }, host="ws-01")
    ]


def privilege_escalation_events():
    return [
        _base(BASE, "iam", "WARNING", "role change", {
            "old_role": "developer", "new_role": "Domain Admins", "target_user": "svc-deploy",
        }, host="srv-01")
    ]


def suspicious_process_events():
    return [
        _base(BASE, "edr", "WARNING", "process", {
            "process": "powershell.exe", "parent_process": "winword.exe",
        }, host="ws-03")
    ]


def dns_anomaly_events():
    return [
        _base(BASE, "dns", "WARNING", "bad domain",
              {"domain": "evil.example", "verdict": "malicious"}, host="ws-01")
    ]


def api_abuse_events(n=110, ip="198.51.100.40"):
    return [
        _base(BASE, "api", "INFO", f"GET /v1/items/{i}",
              {"ip": ip, "endpoint": f"/v1/items/{i % 10}", "method": "GET", "status_code": 200})
        for i in range(n)
    ]


def data_transfer_events():
    return [
        _base(BASE, "firewall", "INFO", "transfer", {
            "bytes_sent": 200 * 1024 * 1024, "direction": "outbound",
            "destination_ip": "203.0.113.99", "ip": "10.0.0.5",
        })
    ]


def account_takeover_events(user="alice"):
    data = [
        _base(BASE + timedelta(seconds=i * 10), "auth-service", "ERROR", "login failed",
              {"user": user, "ip": "10.0.0.5", "action": "login_failed"})
        for i in range(5)
    ]
    data.append(
        _base(BASE + timedelta(seconds=60), "auth-service", "INFO", "login ok",
              {"user": user, "ip": "10.0.0.5", "action": "login_success"})
    )
    return data


def block_burst_events(n=20, ip="203.0.113.50"):
    return [
        _base(BASE + timedelta(seconds=i), "firewall", "WARNING", f"blocked {ip}",
              {"action": "blocked", "source_ip": ip, "destination_port": 1000 + i})
        for i in range(n)
    ]
