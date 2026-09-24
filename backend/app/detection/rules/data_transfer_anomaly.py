"""DataTransferAnomalyRule — large outbound transfer detection.

Detects: a single event reporting >= threshold_bytes with a KNOWN
outbound direction. Both conditions are required:
  - size: extra_data.bytes_sent/bytes numeric and >= threshold_bytes.
    Non-numeric or absent sizes never count (a large number elsewhere
    in the log is not evidence).
  - direction: extra_data.direction in {outbound, egress, upload, out,
    send} (case-insensitive). Unknown or inbound direction never fires.

Language is evidence-based ("Large outbound data transfer detected") —
never "data was stolen". Matches group by (destination, source) so
cooldown dedups repeated runs. Severity from the DetectionRule model
(default HIGH).

Default config: threshold_bytes=104857600 (100 MiB), window_seconds=3600.
"""

from app.detection.base import BaseRule, EvaluationContext, RuleMatch
from app.detection.helpers import extract_source_ip, get_time_window, parse_int

_SIZE_KEYS = ("bytes_sent", "bytes", "bytes_out", "egress_bytes", "tx_bytes")
_DEST_KEYS = ("destination_ip", "destination_domain", "destination", "dest_ip", "dst")
_OUTBOUND = {"outbound", "out", "egress", "upload", "send", "tx"}


def _data(event) -> dict:
    try:
        data = event.extra_data or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _qualifying(event, threshold: int) -> tuple[int, str, str | None] | None:
    """Return (bytes, direction, destination) if the event qualifies."""
    data = _data(event)
    size = None
    for key in _SIZE_KEYS:
        if key in data:
            size = parse_int(data.get(key))
            if size is not None:
                break
    if size is None or size < threshold:
        return None
    direction = data.get("direction")
    if not isinstance(direction, str) or direction.strip().lower() not in _OUTBOUND:
        return None
    dest = None
    for key in _DEST_KEYS:
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            dest = val.strip()
            break
    return (size, direction.strip().lower(), dest or "unknown")


class DataTransferAnomalyRule(BaseRule):
    """Outbound + over-threshold transfer detection, grouped by destination."""

    name = "DataTransferAnomaly"
    rule_type = "data_transfer_anomaly"
    default_config = {
        "threshold_bytes": 104857600,
        "window_seconds": 3600,
    }

    def evaluate(self, ctx: EvaluationContext) -> list[RuleMatch]:
        threshold = int(ctx.rule_config.get("threshold_bytes", self.default_config["threshold_bytes"]))
        window_seconds = int(ctx.rule_config.get("window_seconds", self.default_config["window_seconds"]))
        windowed = get_time_window(ctx.window_events, window_seconds, ctx.evaluation_time)

        groups: dict[str, dict] = {}
        for e in windowed:
            try:
                found = _qualifying(e, threshold)
                src = extract_source_ip(e)
            except Exception:
                continue
            if found is None:
                continue
            size, direction, dest = found
            key = f"exfil:{dest}:{src or 'unknown'}"
            slot = groups.setdefault(
                key,
                {"dest": dest, "src": src or "unknown", "direction": direction, "events": [], "max_bytes": 0},
            )
            slot["events"].append(e)
            slot["max_bytes"] = max(slot["max_bytes"], size)

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
                        "destination": slot["dest"],
                        "source_ip": slot["src"],
                        "direction": slot["direction"],
                        "max_bytes": slot["max_bytes"],
                        "threshold_bytes": threshold,
                        "event_count": len(evs),
                        "window_seconds": window_seconds,
                    },
                    evidence_event_ids=ev_ids,
                    summary=(
                        f"Large outbound data transfer detected to {slot['dest']}: "
                        f"{slot['max_bytes']} bytes (threshold {threshold})"
                    ),
                )
            )
        return matches
