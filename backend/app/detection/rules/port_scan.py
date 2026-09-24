"""PortScanRule — one source IP probing many distinct destination ports.

Detects: a single source contacting >= threshold_ports DISTINCT destination
ports within window_seconds. Counting distinct ports (not events) is what
separates scanning from normal repeated traffic to one port.

Required fields: extra_data.ip (or extra_data.source_ip) + a numeric
extra_data.destination_port (destination_port/dport accepted).
Events missing either are skipped, never counted.

Default config: threshold_ports=10, window_seconds=60.
"""

from app.detection.base import BaseRule, EvaluationContext, RuleMatch
from app.detection.helpers import extract_source_ip, get_time_window, parse_int


def _destination_port(event) -> int | None:
    try:
        data = event.extra_data or {}
        if not isinstance(data, dict):
            return None
        for key in ("destination_port", "dport", "dst_port", "port"):
            if key in data:
                port = parse_int(data.get(key))
                if port is not None and 0 < port < 65536:
                    return port
    except Exception:
        return None
    return None


class PortScanRule(BaseRule):
    """Distinct destination-port counting per source IP."""

    name = "PortScan"
    rule_type = "port_scan"
    default_config = {
        "threshold_ports": 10,
        "window_seconds": 60,
        "group_by": "extra_data.ip",
    }

    def evaluate(self, ctx: EvaluationContext) -> list[RuleMatch]:
        threshold = int(ctx.rule_config.get("threshold_ports", self.default_config["threshold_ports"]))
        window_seconds = int(ctx.rule_config.get("window_seconds", self.default_config["window_seconds"]))
        group_by = str(ctx.rule_config.get("group_by", self.default_config["group_by"]))

        windowed = get_time_window(ctx.window_events, window_seconds, ctx.evaluation_time)

        groups: dict[str, list] = {}
        for e in windowed:
            ip = extract_source_ip(e)
            port = _destination_port(e)
            if ip is None or port is None:
                continue
            groups.setdefault(ip, []).append(e)

        matches: list[RuleMatch] = []
        for ip, evs in groups.items():
            ports = sorted({_destination_port(e) for e in evs if _destination_port(e) is not None})
            if len(ports) >= threshold:
                ev_ids = sorted(e.id for e in evs)
                matches.append(
                    RuleMatch(
                        group_key=f"ip:{ip}",
                        context={
                            "group_key": f"ip:{ip}",
                            "rule_type": self.rule_type,
                            "source_ip": ip,
                            "distinct_ports": len(ports),
                            "ports": ports[:100],
                            "threshold_ports": threshold,
                            "window_seconds": window_seconds,
                            "group_by": group_by,
                        },
                        evidence_event_ids=ev_ids,
                        summary=(
                            f"Port scan pattern detected from {ip}: "
                            f"{len(ports)} distinct ports in {window_seconds}s "
                            f"(threshold {threshold})"
                        ),
                    )
                )
        return matches
