"""DetectionService (M3).

Orchestrates DetectionEngine, handles dedup/cooldown, creates Alert + AlertEvent.
Designed so future scheduler can call run_detection directly.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import select

from app.models.alert import Alert
from app.models.alert_event import AlertEvent
from app.models.detection_rule import DetectionRule
from app.detection.engine import DetectionEngine


def ensure_default_rules(db: Session) -> None:
    """Ensure required default detection rules exist. Idempotent."""
    defaults = [
        {
            "name": "BruteForceLogin",
            "description": "5+ failed logins from same IP within 60 seconds",
            "rule_type": "threshold",
            "config": {
                "threshold": 5,
                "window_seconds": 60,
                "group_by": "extra_data.ip",
                "filter": {"level": "ERROR"},
            },
            "enabled": True,
            "severity": "HIGH",
            "cooldown_seconds": 300,
        },
        {
            "name": "ErrorSpike",
            "description": "ERROR rate spike per service",
            "rule_type": "frequency",
            "config": {
                "min_events": 10,
                "window_seconds": 300,
                "rate_threshold": 20,
                "group_by": "service",
                "filter": {"level": "ERROR"},
            },
            "enabled": True,
            "severity": "MEDIUM",
            "cooldown_seconds": 600,
        },
        {
            "name": "PortScan",
            "description": "One source IP probing 10+ distinct destination ports within 60 seconds",
            "rule_type": "port_scan",
            "config": {
                "threshold_ports": 10,
                "window_seconds": 60,
                "group_by": "extra_data.ip",
            },
            "enabled": True,
            "severity": "HIGH",
            "cooldown_seconds": 300,
        },
        {
            "name": "WebScan",
            "description": "One source IP requesting 8+ distinct suspicious endpoints within 60 seconds",
            "rule_type": "web_scan",
            "config": {
                "threshold_paths": 8,
                "window_seconds": 60,
                "group_by": "extra_data.ip",
            },
            "enabled": True,
            "severity": "MEDIUM",
            "cooldown_seconds": 300,
        },
        {
            "name": "AuthenticationAnomaly",
            "description": "One source IP targeting 5+ distinct accounts within 60 seconds (password spraying)",
            "rule_type": "authentication_anomaly",
            "config": {
                "threshold_accounts": 5,
                "window_seconds": 60,
                "group_by": "extra_data.ip",
            },
            "enabled": True,
            "severity": "HIGH",
            "cooldown_seconds": 300,
        },
        {
            "name": "SQLInjection",
            "description": "SQL injection attempt via explicit telemetry or controlled payload signatures",
            "rule_type": "sql_injection",
            "config": {
                "window_seconds": 300,
            },
            "enabled": True,
            "severity": "HIGH",
            "cooldown_seconds": 300,
        },
        {
            "name": "XSSAttempt",
            "description": "Cross-site scripting attempt via explicit telemetry or controlled payload signatures",
            "rule_type": "xss_attempt",
            "config": {
                "window_seconds": 300,
            },
            "enabled": True,
            "severity": "HIGH",
            "cooldown_seconds": 300,
        },
        {
            "name": "MalwareDetection",
            "description": "Endpoint malware verdict (explicit threat telemetry only, never filenames)",
            "rule_type": "malware_detection",
            "config": {
                "window_seconds": 300,
            },
            "enabled": True,
            "severity": "CRITICAL",
            "cooldown_seconds": 600,
        },
        {
            "name": "PrivilegeEscalation",
            "description": "Suspicious privilege change via explicit action or privileged role transition",
            "rule_type": "privilege_escalation",
            "config": {
                "window_seconds": 300,
            },
            "enabled": True,
            "severity": "HIGH",
            "cooldown_seconds": 600,
        },
        {
            "name": "SuspiciousProcess",
            "description": "Suspicious process execution via explicit verdict or controlled indicator combos",
            "rule_type": "suspicious_process",
            "config": {
                "window_seconds": 300,
            },
            "enabled": True,
            "severity": "HIGH",
            "cooldown_seconds": 600,
        },
        {
            "name": "DNSAnomaly",
            "description": "Suspicious DNS verdicts or 50+ distinct domains per host within 300 seconds",
            "rule_type": "dns_anomaly",
            "config": {
                "threshold_unique_domains": 50,
                "window_seconds": 300,
            },
            "enabled": True,
            "severity": "MEDIUM",
            "cooldown_seconds": 600,
        },
        {
            "name": "APIAbuse",
            "description": "Client IP issuing 100+ API requests within 60 seconds",
            "rule_type": "api_abuse",
            "config": {
                "threshold_requests": 100,
                "window_seconds": 60,
                "group_by": "extra_data.ip",
            },
            "enabled": True,
            "severity": "MEDIUM",
            "cooldown_seconds": 600,
        },
        {
            "name": "DataTransferAnomaly",
            "description": "Single outbound transfer at/above 100 MiB (explicit size + outbound direction required)",
            "rule_type": "data_transfer_anomaly",
            "config": {
                "threshold_bytes": 104857600,
                "window_seconds": 3600,
            },
            "enabled": True,
            "severity": "HIGH",
            "cooldown_seconds": 600,
        },
        {
            "name": "AccountTakeover",
            "description": "5+ failures for one account followed by a successful login within 300 seconds",
            "rule_type": "account_takeover",
            "config": {
                "fail_threshold": 5,
                "window_seconds": 300,
            },
            "enabled": True,
            "severity": "HIGH",
            "cooldown_seconds": 900,
        },
        {
            "name": "SecurityBlockBurst",
            "description": "20+ blocked connections from one source within 60 seconds (explicit block actions only)",
            "rule_type": "security_block_burst",
            "config": {
                "threshold_blocks": 20,
                "window_seconds": 60,
                "group_by": "extra_data.source_ip",
            },
            "enabled": True,
            "severity": "MEDIUM",
            "cooldown_seconds": 300,
        },
    ]

    for rule_data in defaults:
        existing = db.execute(select(DetectionRule).where(DetectionRule.name == rule_data["name"])).scalars().first()
        if not existing:
            rule = DetectionRule(**rule_data)
            db.add(rule)
    db.commit()


class DetectionService:
    """Service layer for detection execution and alert persistence."""

    def __init__(self, engine: DetectionEngine):
        self.engine = engine

    def run_detection(
        self,
        db: Session,
        window_seconds: int = 300,
        evaluation_time: Optional[datetime] = None,
        rule_names: Optional[list[str]] = None,
    ) -> list[Alert]:
        """Run detection and persist alerts with dedup.

        Returns list of newly created alerts.
        """
        if evaluation_time is None:
            evaluation_time = datetime.now(timezone.utc)
        if evaluation_time.tzinfo is None:
            evaluation_time = evaluation_time.replace(tzinfo=timezone.utc)

        matches = self.engine.scan_recent(
            db=db,
            window_seconds=window_seconds,
            evaluation_time=evaluation_time,
            rule_names=rule_names,
        )

        new_alerts: list[Alert] = []
        for item in matches:
            rule = item["rule"]
            rule_model: DetectionRule = item["rule_model"]
            match = item["match"]

            # Dedup: check cooldown per (rule_id, group_key)
            if self._is_in_cooldown(db, rule_model, match.group_key, evaluation_time):
                continue

            # Create Alert
            # evidence ids already sorted by rule
            first_id = match.evidence_event_ids[0] if match.evidence_event_ids else 0
            last_id = match.evidence_event_ids[-1] if match.evidence_event_ids else 0
            alert = Alert(
                rule_id=rule_model.id,
                rule_name=rule_model.name,
                status="detected",
                severity=rule_model.severity,
                detected_at=evaluation_time,
                summary=match.summary,
                context=match.context,
                first_event_id=first_id,
                last_event_id=last_id,
            )
            db.add(alert)
            db.flush()  # get alert.id

            # Create AlertEvent links
            for eid in match.evidence_event_ids:
                ae = AlertEvent(alert_id=alert.id, event_id=eid)
                db.add(ae)

            new_alerts.append(alert)

        db.commit()
        return new_alerts

    def _is_in_cooldown(
        self,
        db: Session,
        rule_model: DetectionRule,
        group_key: str,
        evaluation_time: datetime,
    ) -> bool:
        cutoff = evaluation_time - timedelta(seconds=rule_model.cooldown_seconds)
        # Status in detected or acknowledged prevents new alert
        # SQLite JSON: need to handle context as JSON text; use simple Python filter for portability
        # Query all recent alerts for rule, filter in Python for portability
        recent = db.execute(
            select(Alert).where(Alert.rule_id == rule_model.id).where(Alert.detected_at >= cutoff)
        ).scalars().all()
        for a in recent:
            if a.status not in ("detected", "acknowledged"):
                continue
            ctx = a.context or {}
            if ctx.get("group_key") == group_key:
                return True
        return False
