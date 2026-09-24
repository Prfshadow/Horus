"""SourceIpStrategy (M4)."""

from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import select

from app.correlation.base import CorrelationStrategy
from app.models.alert import Alert
from app.models.alert_event import AlertEvent
from app.models.event import Event


class SourceIpStrategy(CorrelationStrategy):
    """Extract IP for correlation.

    Priority:
      1. alert.context["group_key"] (BruteForceLogin)
      2. evidence Event.extra_data["ip"] (unique or skip if ambiguous)

    Key: "ip:<value>"
    """

    name = "source_ip"

    def extract_key(self, alert: Alert, db: Session) -> Optional[str]:
        # 1. group_key from context (BruteForceLogin)
        ctx = alert.context or {}
        group_key = ctx.get("group_key")
        if group_key is not None and ctx.get("group_by") == "extra_data.ip":
            # Assume group_key is IP-like; use it directly
            ip = str(group_key).strip()
            if ip:
                return f"ip:{ip}"
        # Also handle case where group_key is IP even if group_by differs? Keep strict: only if group_by is ip path
        # Fallback: if context has group_key and no group_by, treat as potential IP if rule is BruteForceLogin
        if group_key is not None and alert.rule_name == "BruteForceLogin":
            ip = str(group_key).strip()
            if ip:
                # Check if ip looks like IP (simple)
                if "." in ip or ":" in ip:
                    return f"ip:{ip}"

        # 2. Evidence events extra_data["ip"]
        # Load linked events
        alert_id = alert.id
        # Use db to fetch AlertEvents
        links = db.execute(select(AlertEvent).where(AlertEvent.alert_id == alert_id)).scalars().all()
        ips: set[str] = set()
        for link in links:
            ev = db.get(Event, link.event_id)
            if ev and ev.extra_data and "ip" in ev.extra_data:
                val = ev.extra_data.get("ip")
                if val is not None:
                    ips.add(str(val).strip())
        if not ips:
            return None
        if len(ips) > 1:
            # ambiguous
            return None
        ip = next(iter(ips))
        if not ip:
            return None
        return f"ip:{ip}"
