"""PrivilegeEscalationRule — suspicious privilege-change detection.

Detects: a meaningful privilege transition described by structured
telemetry. Two conservative triggers (either suffices):
  1. Explicit action: extra_data.action in a controlled allowlist
     (grant_admin, sudo, role_assigned, privilege_escalated, ...).
  2. Role transition: extra_data.old_role -> extra_data.new_role where the
     new role is in the privileged set and differs from the old role.

Ordinary role assignments between non-privileged roles never fire, and
message prose alone (no structured fields) never fires.

Grouped by target user (fallback: actor, then host). Severity comes from
the DetectionRule model (default HIGH).

Default config: window_seconds=300.
"""

from app.detection.base import BaseRule, EvaluationContext, RuleMatch
from app.detection.helpers import get_time_window

_ESCALATION_ACTIONS = {
    "grant_admin",
    "grant-administrator",
    "add_to_admins",
    "add-to-administrators",
    "sudo",
    "sudo_command",
    "runas",
    "run_as_admin",
    "role_assigned",
    "privilege_escalated",
    "became_root",
    "elevated_token",
}

_PRIVILEGED_ROLES = {
    "admin",
    "administrator",
    "administrators",
    "root",
    "sudo",
    "wheel",
    "superuser",
    "domain admins",
    "domain_admins",
    "enterprise admins",
    "enterprise_admins",
    "schema admins",
}


def _data(event) -> dict:
    try:
        data = event.extra_data or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _norm(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().lower()


def _transition(event) -> tuple[str, str] | None:
    """Return (indicator, detail) for a privilege escalation, else None."""
    data = _data(event)

    action = _norm(data.get("action"))
    if action is not None and action in _ESCALATION_ACTIONS:
        return ("explicit-action", f"action={action}")

    old_role = _norm(data.get("old_role"))
    new_role = _norm(data.get("new_role"))
    if new_role is not None and new_role in _PRIVILEGED_ROLES and new_role != old_role:
        return ("role-transition", f"{old_role or '?'}->{new_role}")
    return None


def _subject(event) -> str | None:
    data = _data(event)
    for key in ("target_user", "user", "username", "account"):
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    actor = data.get("actor")
    if isinstance(actor, str) and actor.strip():
        return f"actor:{actor.strip()}"
    host = event.host
    if isinstance(host, str) and host.strip():
        return f"host:{host.strip()}"
    return None


class PrivilegeEscalationRule(BaseRule):
    """Structured privilege-transition detection, grouped by subject."""

    name = "PrivilegeEscalation"
    rule_type = "privilege_escalation"
    default_config = {
        "window_seconds": 300,
    }

    def evaluate(self, ctx: EvaluationContext) -> list[RuleMatch]:
        window_seconds = int(ctx.rule_config.get("window_seconds", self.default_config["window_seconds"]))
        windowed = get_time_window(ctx.window_events, window_seconds, ctx.evaluation_time)

        groups: dict[str, dict] = {}
        for e in windowed:
            try:
                found = _transition(e)
                subject = _subject(e)
            except Exception:
                continue
            if found is None or subject is None:
                continue
            indicator, detail = found
            key = f"privesc:{subject}:{indicator}"
            slot = groups.setdefault(
                key, {"subject": subject, "indicator": indicator, "detail": detail, "events": []}
            )
            slot["events"].append(e)

        matches: list[RuleMatch] = []
        for key, slot in groups.items():
            evs = slot["events"]
            ev_ids = sorted(e.id for e in evs)
            matches.append(
                RuleMatch(
                    group_key=key,
                    context={
                        "group_key": key,
                        "rule_type": self.rule_type,
                        "subject": slot["subject"],
                        "indicator": slot["indicator"],
                        "detail": slot["detail"],
                        "event_count": len(evs),
                        "window_seconds": window_seconds,
                    },
                    evidence_event_ids=ev_ids,
                    summary=(
                        f"Privilege escalation pattern detected for {slot['subject']}: "
                        f"{slot['detail']} ({len(evs)} events)"
                    ),
                )
            )
        return matches
