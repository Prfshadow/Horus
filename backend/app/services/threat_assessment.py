"""Threat Assessment Service.

Orchestrates the full detection pipeline and produces a user-facing threat assessment.
Uses only deterministic evidence: alert/incident severities, never LLM output.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Incident
from app.models.incident_alert import IncidentAlert
from app.services.detection import DetectionService
from app.services.incident_correlation import IncidentCorrelationService
from app.detection.engine import DetectionEngine
from app.correlation.engine import IncidentCorrelationEngine

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Forensic sweep of scoped uploads: evaluation anchors step through the
# referenced span so attacks older than any single rule window are still
# found. Capped so pathological spans stay bounded.
_SCOPED_ANCHOR_STEP_SECONDS = 30.0
_SCOPED_MAX_ANCHORS = 240


def _scoped_evaluation_anchors(events: list[Event]) -> list[datetime]:
    """Evaluation timestamps sweeping a scoped upload, oldest -> newest.

    The newest referenced event is always included. Cooldown dedup in
    run_detection keeps one ongoing attack to exactly one alert.
    """
    stamps = []
    for e in events:
        ts = e.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        stamps.append(ts)
    start, end = min(stamps), max(stamps)
    span = max(0.0, (end - start).total_seconds())
    step = _SCOPED_ANCHOR_STEP_SECONDS
    count = int(span // step) + 1
    if count > _SCOPED_MAX_ANCHORS:
        step = span / (_SCOPED_MAX_ANCHORS - 1)
        count = _SCOPED_MAX_ANCHORS
    anchors = [start + timedelta(seconds=i * step) for i in range(count)]
    if anchors[-1] < end:
        anchors.append(end)
    return anchors

RULE_EXPLANATIONS = {
    "BruteForceLogin": "Repeated authentication failures from the same source",
    "ErrorSpike": "Unusual spike in error rates for a service",
    "PortScan": "One source probing many destination ports",
    "WebScan": "One source requesting many suspicious endpoints",
    "AuthenticationAnomaly": "One source targeting many different accounts (password spraying)",
    "SQLInjection": "SQL injection attempt detected",
    "XSSAttempt": "Cross-site scripting attempt detected",
    "MalwareDetection": "Malware verdict from endpoint telemetry",
    "PrivilegeEscalation": "Suspicious privilege change or role transition",
    "SuspiciousProcess": "Suspicious process execution detected",
    "DNSAnomaly": "Suspicious DNS activity or excessive domain queries",
    "APIAbuse": "Excessive API requests from a single source",
    "DataTransferAnomaly": "Large outbound data transfer detected",
    "AccountTakeover": "Failed logins followed by successful login for same account",
    "SecurityBlockBurst": "Many blocked connections from one source",
}

RULE_TITLES = {
    "AccountTakeover": "Possible Account Compromise",
    "BruteForceLogin": "Possible Brute-Force Attack",
    "AuthenticationAnomaly": "Possible Password Spraying",
    "PortScan": "Possible Network Reconnaissance",
    "WebScan": "Possible Web Reconnaissance",
    "SQLInjection": "Possible SQL Injection Attack",
    "XSSAttempt": "Possible Cross-Site Scripting Attack",
    "MalwareDetection": "Possible Malware Infection",
    "PrivilegeEscalation": "Possible Privilege Escalation",
    "SuspiciousProcess": "Suspicious Endpoint Activity",
    "DNSAnomaly": "Suspicious DNS Activity",
    "APIAbuse": "Possible API Abuse",
    "DataTransferAnomaly": "Possible Data Exfiltration",
    "ErrorSpike": "Service Error Spike",
    "SecurityBlockBurst": "Blocked Connection Burst",
}


class ThreatAssessment:
    """Result of threat assessment."""

    def __init__(
        self,
        threat_level: str,
        threat_title: str,
        explanation: str,
        details: list[str],
        alerts_count: int,
        incidents_count: int,
        events_analyzed: int,
        alert_severities: dict[str, int],
        incident_severities: dict[str, int],
        affected_entities: dict[str, list[str]],
        synthetic: bool = False,
        alert_ids: Optional[list[int]] = None,
        incident_ids: Optional[list[int]] = None,
    ):
        self.threat_level = threat_level
        self.threat_title = threat_title
        self.explanation = explanation
        self.details = details
        self.alerts_count = alerts_count
        self.incidents_count = incidents_count
        self.events_analyzed = events_analyzed
        self.alert_severities = alert_severities
        self.incident_severities = incident_severities
        self.affected_entities = affected_entities
        self.synthetic = synthetic
        self.alert_ids = alert_ids or []
        self.incident_ids = incident_ids or []

    def to_dict(self) -> dict:
        return {
            "threat_level": self.threat_level,
            "threat_title": self.threat_title,
            "explanation": self.explanation,
            "details": self.details,
            "alerts_count": self.alerts_count,
            "incidents_count": self.incidents_count,
            "events_analyzed": self.events_analyzed,
            "alert_severities": self.alert_severities,
            "incident_severities": self.incident_severities,
            "affected_entities": self.affected_entities,
            "synthetic": self.synthetic,
            "alert_ids": self.alert_ids,
            "incident_ids": self.incident_ids,
        }


def _max_severity(severities: list[str]) -> str:
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    max_s = "LOW"
    max_val = -1
    for s in severities:
        v = order.get(s.upper(), -1)
        if v > max_val:
            max_val = v
            max_s = s.upper()
    return max_s


def _compute_threat_level(
    alert_severities: dict[str, int],
    incident_severities: dict[str, int],
    alerts_count: int,
    incidents_count: int,
) -> str:
    """Simple maximum-severity approach over deterministic evidence."""
    if incidents_count > 0 and incident_severities:
        expanded: list[str] = []
        for sev, count in incident_severities.items():
            expanded.extend([sev] * count)
        return _max_severity(expanded)
    if alerts_count > 0 and alert_severities:
        expanded = []
        for sev, count in alert_severities.items():
            expanded.extend([sev] * count)
        return _max_severity(expanded)
    return "LOW"


def _generate_explanation(
    threat_level: str,
    alerts: list[Alert],
    incidents: list[Incident],
) -> tuple[str, str, list[str]]:
    """Generate (title, explanation, details) from actual detected evidence."""
    if not alerts and not incidents:
        return (
            "No Significant Threat Detected",
            "HORUS analyzed the events and found no configured detection conditions.",
            ["All events passed through detection rules without triggering alerts."],
        )

    # Group alerts by rule
    rule_counts: dict[str, int] = {}
    for alert in alerts:
        rule_counts[alert.rule_name] = rule_counts.get(alert.rule_name, 0) + 1

    # Get unique explanations from rules
    seen_explanations = set()
    details = []
    for rule_name, count in sorted(rule_counts.items(), key=lambda x: -x[1]):
        explanation = RULE_EXPLANATIONS.get(rule_name, rule_name)
        if explanation not in seen_explanations:
            seen_explanations.add(explanation)
            details.append(f"{explanation} ({count} alert{'s' if count > 1 else ''})")

    # Generate threat title from top evidence (human-readable, no rule internals)
    if incidents:
        # Title from the most frequent rule behind the incident's alerts
        top_rule = max(rule_counts.items(), key=lambda x: x[1])[0] if rule_counts else None
        threat_title = RULE_TITLES.get(top_rule, "Correlated Security Incident") if top_rule else "Correlated Security Incident"
    elif alerts:
        top_rule = max(rule_counts.items(), key=lambda x: x[1])[0]
        threat_title = RULE_TITLES.get(top_rule, RULE_EXPLANATIONS.get(top_rule, top_rule))
    else:
        threat_title = "Security Event"

    # Build explanation
    if threat_level == "LOW":
        explanation = "HORUS found limited suspicious activity that warrants awareness."
    elif threat_level == "MEDIUM":
        explanation = "HORUS detected clearly suspicious activity requiring investigation."
    elif threat_level == "HIGH":
        explanation = "HORUS found strong evidence of compromise or a significant security event."
    else:
        explanation = "HORUS detected multiple serious indicators forming a potentially severe incident."

    explanation = (
        f"{explanation}\n\n{len(alerts)} alert{'s' if len(alerts) != 1 else ''} detected "
        f"across {len(rule_counts)} detection categor{'y' if len(rule_counts) == 1 else 'ies'}."
    )
    return threat_title, explanation, details


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _collect_affected_entities(alerts: list[Alert], incidents: list[Incident]) -> dict[str, list[str]]:
    """Collect affected IPs, hosts, users from alerts and incidents."""
    ips = set()
    hosts = set()
    users = set()

    def _add_group_key(gk: object) -> None:
        if not isinstance(gk, str) or not gk:
            return
        # Known formats: "ip:1.2.3.4", "1.2.3.4", "host:web-01", "blockburst:1.2.3.4",
        # "privesc:alice:explicit-action", service names.
        if gk.startswith("ip:"):
            ips.add(gk[3:])
            return
        if gk.startswith("host:"):
            hosts.add(gk[5:])
            return
        if gk.startswith("blockburst:"):
            ips.add(gk.split(":", 1)[1])
            return
        if gk.startswith("privesc:"):
            subject = gk.split(":")[1] if len(gk.split(":")) > 1 else ""
            if subject.startswith("host:"):
                hosts.add(subject[5:])
            elif subject.startswith("actor:"):
                users.add(subject[6:])
            elif subject:
                users.add(subject)
            return
        if _looks_like_ip(gk):
            ips.add(gk)

    for alert in alerts:
        ctx = alert.context or {}
        for key in ("ip", "source_ip", "destination_ip"):
            val = ctx.get(key)
            if isinstance(val, str) and val:
                ips.add(val)
        for key in ("user", "target_user", "username", "account"):
            val = ctx.get(key)
            if isinstance(val, str) and val:
                users.add(val)
        actor = ctx.get("actor")
        if isinstance(actor, str) and actor:
            users.add(actor)
        subject = ctx.get("subject")
        if isinstance(subject, str) and subject:
            # SuspiciousProcess subjects are hosts; privilege subjects are users.
            if ctx.get("rule_type") == "suspicious_process":
                hosts.add(subject)
            elif subject.startswith("host:"):
                hosts.add(subject[5:])
            elif subject.startswith("actor:"):
                users.add(subject[6:])
            else:
                users.add(subject)
        host_val = ctx.get("host")
        if isinstance(host_val, str) and host_val:
            hosts.add(host_val)
        _add_group_key(ctx.get("group_key"))

    for incident in incidents:
        _add_group_key(incident.correlation_key)

    return {
        "ips": sorted(ips) if ips else [],
        "hosts": sorted(hosts) if hosts else [],
        "users": sorted(users) if users else [],
    }


class ThreatAssessmentService:
    """Runs the full detection pipeline and produces a threat assessment."""

    def __init__(
        self,
        detection_engine: Optional[DetectionEngine] = None,
        correlation_engine: Optional[IncidentCorrelationEngine] = None,
    ):
        self.detection_service = DetectionService(detection_engine or DetectionEngine())
        self.correlation_service = IncidentCorrelationService(correlation_engine or IncidentCorrelationEngine())

    def assess(
        self,
        db: Session,
        window_seconds: int = 300,
        correlation_window_seconds: int = 3600,
        evaluation_time: Optional[datetime] = None,
        correlation_strategy: str = "source_ip",
        rule_names: Optional[list[str]] = None,
        synthetic: bool = False,
        event_ids: Optional[list[int]] = None,
    ) -> ThreatAssessment:
        """Run full detection pipeline and produce threat assessment.

        When ``event_ids`` is given, the assessment is scoped to exactly those
        ingested events: evaluation_time defaults to the newest referenced
        event (so uploads with their own timestamps are analyzed regardless
        of the server clock), only incidents linked to alerts created in this
        run are reported, and events_analyzed counts the referenced events.
        """
        # An explicitly passed evaluation_time keeps legacy single-run
        # behavior; only defaulted scoped assessments sweep the span.
        explicit_evaluation_time = evaluation_time is not None
        scoped_events: Optional[list[Event]] = None
        if event_ids is not None:
            # Deduplicate while preserving order.
            seen: set[int] = set()
            unique_ids = [i for i in event_ids if not (i in seen or seen.add(i))]
            if not unique_ids:
                return ThreatAssessment(
                    threat_level="LOW",
                    threat_title="No Events Provided",
                    explanation="No events were provided for assessment. Ingest log lines first, then assess.",
                    details=["No event IDs were supplied with this assessment request."],
                    alerts_count=0,
                    incidents_count=0,
                    events_analyzed=0,
                    alert_severities={},
                    incident_severities={},
                    affected_entities={"ips": [], "hosts": [], "users": []},
                    synthetic=synthetic,
                )
            rows = db.execute(select(Event).where(Event.id.in_(unique_ids))).scalars().all()
            found = {e.id: e for e in rows}
            scoped_events = [found[i] for i in unique_ids if i in found]
            if not scoped_events:
                return ThreatAssessment(
                    threat_level="LOW",
                    threat_title="Events Not Found",
                    explanation="The referenced events were not found. They may have been deleted.",
                    details=["No matching events exist for the supplied event IDs."],
                    alerts_count=0,
                    incidents_count=0,
                    events_analyzed=0,
                    alert_severities={},
                    incident_severities={},
                    affected_entities={"ips": [], "hosts": [], "users": []},
                    synthetic=synthetic,
                )
            if evaluation_time is None:
                latest = scoped_events[0].timestamp
                for ev in scoped_events[1:]:
                    if ev.timestamp > latest:
                        latest = ev.timestamp
                if latest.tzinfo is None:
                    latest = latest.replace(tzinfo=timezone.utc)
                evaluation_time = latest

        if evaluation_time is None:
            evaluation_time = datetime.now(timezone.utc)
        if evaluation_time.tzinfo is None:
            evaluation_time = evaluation_time.replace(tzinfo=timezone.utc)

        # Step 1: Run detection
        if scoped_events is not None and not explicit_evaluation_time:
            # Forensic sweep: a scoped upload can span far longer than any
            # single rule window, so evaluate at successive anchors across
            # the referenced span (oldest -> newest). Cooldown dedup keeps
            # one ongoing attack to exactly one alert. Correlation below
            # still runs once, at the newest referenced event.
            alerts: list[Alert] = []
            for anchor in _scoped_evaluation_anchors(scoped_events):
                alerts.extend(
                    self.detection_service.run_detection(
                        db=db,
                        window_seconds=window_seconds,
                        evaluation_time=anchor,
                        rule_names=rule_names,
                    )
                )
        else:
            alerts = self.detection_service.run_detection(
                db=db,
                window_seconds=window_seconds,
                evaluation_time=evaluation_time,
                rule_names=rule_names,
            )

        # Step 2: Run correlation
        correlation_result = self.correlation_service.run_correlation(
            db=db,
            window_seconds=correlation_window_seconds,
            evaluation_time=evaluation_time,
            strategy=correlation_strategy,
            rule_names=rule_names,
        )
        incidents = correlation_result["incidents"]

        if scoped_events is not None:
            # Report only incidents linked to alerts created in this run, so
            # the assessment describes the current upload — not stale history.
            new_alert_ids = {a.id for a in alerts}
            scoped_incidents = []
            for inc in incidents:
                linked = {
                    r[0]
                    for r in db.execute(
                        select(IncidentAlert.alert_id).where(IncidentAlert.incident_id == inc.id)
                    ).all()
                }
                if linked & new_alert_ids:
                    scoped_incidents.append(inc)
            incidents = scoped_incidents

        # Compute severities
        alert_severities: dict[str, int] = {}
        for alert in alerts:
            alert_severities[alert.severity] = alert_severities.get(alert.severity, 0) + 1

        incident_severities: dict[str, int] = {}
        for incident in incidents:
            incident_severities[incident.severity] = incident_severities.get(incident.severity, 0) + 1

        # Compute threat level
        threat_level = _compute_threat_level(
            alert_severities, incident_severities, len(alerts), len(incidents)
        )

        # Generate explanation
        threat_title, explanation, details = _generate_explanation(threat_level, alerts, incidents)

        # Collect affected entities
        affected_entities = _collect_affected_entities(alerts, incidents)

        if scoped_events is not None:
            # The assessment describes exactly the referenced upload.
            events_analyzed_count = len(scoped_events)
        else:
            # Count events in the detection window (not just alert evidence, so
            # no-threat assessments still report "events analyzed").
            cutoff = evaluation_time - timedelta(seconds=window_seconds)
            events_analyzed = db.execute(
                select(Event.id)
                .where(Event.timestamp >= cutoff)
                .where(Event.timestamp <= evaluation_time)
            ).all()
            events_analyzed_count = len(events_analyzed)

        return ThreatAssessment(
            threat_level=threat_level,
            threat_title=threat_title,
            explanation=explanation,
            details=details,
            alerts_count=len(alerts),
            incidents_count=len(incidents),
            events_analyzed=events_analyzed_count,
            alert_severities=alert_severities,
            incident_severities=incident_severities,
            affected_entities=affected_entities,
            synthetic=synthetic,
            alert_ids=[a.id for a in alerts],
            incident_ids=[i.id for i in incidents],
        )


def assess_threats(
    db: Session,
    window_seconds: int = 300,
    correlation_window_seconds: int = 3600,
    evaluation_time: Optional[datetime] = None,
    correlation_strategy: str = "source_ip",
    rule_names: Optional[list[str]] = None,
    synthetic: bool = False,
    event_ids: Optional[list[int]] = None,
) -> ThreatAssessment:
    """Convenience function to run threat assessment."""
    service = ThreatAssessmentService()
    return service.assess(
        db=db,
        window_seconds=window_seconds,
        correlation_window_seconds=correlation_window_seconds,
        evaluation_time=evaluation_time,
        correlation_strategy=correlation_strategy,
        rule_names=rule_names,
        synthetic=synthetic,
        event_ids=event_ids,
    )