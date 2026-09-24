"""APIAbuseRule — abnormal API request-volume detection.

Detects: a single client IP issuing >= threshold_requests API-shaped
requests within window_seconds. An event counts as an API request only
when it carries API telemetry: extra_data.endpoint, or a (method +
status_code) pair. Plain log volume without API structure never fires.

Rate-limit signals (extra_data.rate_limited truthy) are counted and
reported in context but do not change the threshold — volume alone is
the trigger.

Grouped by source IP. Severity from the DetectionRule model
(default MEDIUM).

Default config: threshold_requests=100, window_seconds=60.
"""

from app.detection.base import BaseRule, EvaluationContext, RuleMatch
from app.detection.helpers import extract_source_ip, get_time_window


def _data(event) -> dict:
    try:
        data = event.extra_data or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _is_api_request(event) -> bool:
    data = _data(event)
    endpoint = data.get("endpoint")
    if isinstance(endpoint, str) and endpoint.strip():
        return True
    method = data.get("method")
    status = data.get("status_code")
    return isinstance(method, str) and method.strip() != "" and status is not None


def _rate_limited(event) -> bool:
    data = _data(event)
    val = data.get("rate_limited")
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("true", "1", "yes")
    return False


class APIAbuseRule(BaseRule):
    """Per-client-IP API request volume counting."""

    name = "APIAbuse"
    rule_type = "api_abuse"
    default_config = {
        "threshold_requests": 100,
        "window_seconds": 60,
        "group_by": "extra_data.ip",
    }

    def evaluate(self, ctx: EvaluationContext) -> list[RuleMatch]:
        threshold = int(ctx.rule_config.get("threshold_requests", self.default_config["threshold_requests"]))
        window_seconds = int(ctx.rule_config.get("window_seconds", self.default_config["window_seconds"]))
        group_by = str(ctx.rule_config.get("group_by", self.default_config["group_by"]))

        windowed = get_time_window(ctx.window_events, window_seconds, ctx.evaluation_time)

        groups: dict[str, list] = {}
        for e in windowed:
            try:
                if not _is_api_request(e):
                    continue
                ip = extract_source_ip(e)
            except Exception:
                continue
            if ip is None:
                continue
            groups.setdefault(ip, []).append(e)

        matches: list[RuleMatch] = []
        for ip, evs in groups.items():
            if len(evs) < threshold:
                continue
            limited = sum(1 for e in evs if _rate_limited(e))
            endpoints: dict[str, int] = {}
            for e in evs:
                try:
                    ep = _data(e).get("endpoint")
                except Exception:
                    ep = None
                if isinstance(ep, str) and ep.strip():
                    endpoints.setdefault(ep.strip(), e.id)
            matches.append(
                RuleMatch(
                    group_key=f"ip:{ip}",
                    context={
                        "group_key": f"ip:{ip}",
                        "rule_type": self.rule_type,
                        "source_ip": ip,
                        "request_count": len(evs),
                        "distinct_endpoints": len(endpoints),
                        "rate_limited_count": limited,
                        "threshold_requests": threshold,
                        "window_seconds": window_seconds,
                        "group_by": group_by,
                    },
                    evidence_event_ids=sorted(e.id for e in evs),
                    summary=(
                        f"API abuse pattern detected from {ip}: "
                        f"{len(evs)} requests in {window_seconds}s "
                        f"(threshold {threshold})"
                    ),
                )
            )
        return matches
