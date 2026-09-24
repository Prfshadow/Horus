"""SecurityBlockBurstRule — firewall/security block burst detection.

Detects: >= threshold_blocks block actions from one source within
window_seconds. A block counts only with an EXPLICIT structured action
(extra_data.action in {blocked, block, denied, deny, dropped, drop,
rejected, quarantined}, case-insensitive). Message prose mentioning
"blocked" never counts.

Grouped by source IP (extra_data.source_ip, fallback extra_data.ip).
Distinct destination ports are reported in context when present.
Severity comes from the DetectionRule model (default MEDIUM).

Default config: threshold_blocks=20, window_seconds=60.
"""

from app.detection.base import BaseRule, EvaluationContext, RuleMatch
from app.detection.helpers import get_time_window, parse_int

_BLOCK_ACTIONS = {
    "blocked",
    "block",
    "denied",
    "deny",
    "dropped",
    "drop",
    "rejected",
    "reject",
    "quarantined",
    "quarantine",
}


def _data(event) -> dict:
    try:
        data = event.extra_data or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _block_source(event) -> str | None:
    data = _data(event)
    action = data.get("action")
    if not isinstance(action, str) or action.strip().lower() not in _BLOCK_ACTIONS:
        return None
    for key in ("source_ip", "ip"):
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def _dst_port(event) -> int | None:
    data = _data(event)
    for key in ("destination_port", "dport", "dst_port"):
        if key in data:
            port = parse_int(data.get(key))
            if port is not None and 0 < port < 65536:
                return port
    return None


class SecurityBlockBurstRule(BaseRule):
    """Per-source explicit block-action counting."""

    name = "SecurityBlockBurst"
    rule_type = "security_block_burst"
    default_config = {
        "threshold_blocks": 20,
        "window_seconds": 60,
        "group_by": "extra_data.source_ip",
    }

    def evaluate(self, ctx: EvaluationContext) -> list[RuleMatch]:
        threshold = int(ctx.rule_config.get("threshold_blocks", self.default_config["threshold_blocks"]))
        window_seconds = int(ctx.rule_config.get("window_seconds", self.default_config["window_seconds"]))
        group_by = str(ctx.rule_config.get("group_by", self.default_config["group_by"]))

        windowed = get_time_window(ctx.window_events, window_seconds, ctx.evaluation_time)

        groups: dict[str, list] = {}
        for e in windowed:
            try:
                ip = _block_source(e)
            except Exception:
                continue
            if ip is None:
                continue
            groups.setdefault(ip, []).append(e)

        matches: list[RuleMatch] = []
        for ip, evs in groups.items():
            if len(evs) < threshold:
                continue
            ports = sorted({_dst_port(e) for e in evs if _dst_port(e) is not None})
            matches.append(
                RuleMatch(
                    group_key=f"blockburst:{ip}",
                    context={
                        "group_key": f"blockburst:{ip}",
                        "rule_type": self.rule_type,
                        "source_ip": ip,
                        "block_count": len(evs),
                        "distinct_destination_ports": len(ports),
                        "threshold_blocks": threshold,
                        "window_seconds": window_seconds,
                        "group_by": group_by,
                    },
                    evidence_event_ids=sorted(e.id for e in evs),
                    summary=(
                        f"Security block burst from {ip}: "
                        f"{len(evs)} blocked connections in {window_seconds}s "
                        f"(threshold {threshold})"
                    ),
                )
            )
        return matches
