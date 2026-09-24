"""HostStrategy (M4)."""

from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import select

from app.correlation.base import CorrelationStrategy
from app.models.alert import Alert
from app.models.alert_event import AlertEvent
from app.models.event import Event


class HostStrategy(CorrelationStrategy):
    """Extract host for correlation.

    Priority:
      1. Event.host
      2. Event.extra_data["host"] fallback
    If multiple conflicting non-null hosts -> skip.
    Key: "host:<value>"
    """

    name = "host"

    def extract_key(self, alert: Alert, db: Session) -> Optional[str]:
        links = db.execute(select(AlertEvent).where(AlertEvent.alert_id == alert.id)).scalars().all()
        hosts: set[str] = set()
        for link in links:
            ev = db.get(Event, link.event_id)
            if not ev:
                continue
            h = ev.host
            if h:
                hosts.add(str(h).strip())
            elif ev.extra_data and "host" in ev.extra_data:
                val = ev.extra_data.get("host")
                if val is not None:
                    hosts.add(str(val).strip())
        if not hosts:
            return None
        if len(hosts) > 1:
            return None
        host = next(iter(hosts))
        if not host:
            return None
        return f"host:{host}"
