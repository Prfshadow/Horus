"""DNSAnomalyRule — suspicious DNS behavior detection.

Detects (either suffices):
  1. Explicit verdict: extra_data.verdict/category in a controlled
     malicious set ({malicious, dga, tunneling, suspicious, c2}) with a
     domain/query present.
  2. Behavioral: one host issuing queries for >= threshold_unique_domains
     DISTINCT domains within window_seconds (DGA/tunneling shape).
     Repeated queries for the SAME domain never fire — only distinct
     breadth counts.

DNS fields: extra_data.domain/domain/query (or query_count is ignored as
a trigger; only observed distinct domains count). Host identity: the
Event.host column, falling back to extra_data.host.

Grouped by domain (verdict mode) or host (behavior mode). Severity from
the DetectionRule model (default MEDIUM; verdict details stay in
context for operator review).

Default config: threshold_unique_domains=50, window_seconds=300.
"""

from app.detection.base import BaseRule, EvaluationContext, RuleMatch
from app.detection.helpers import get_time_window

_MALICIOUS_VERDICTS = {"malicious", "dga", "tunneling", "tunnel", "suspicious", "c2", "command-and-control"}

_DOMAIN_KEYS = ("domain", "query", "qname", "hostname_queried")
_HOST_KEYS = ("host", "hostname", "source_ip", "client_ip")


def _data(event) -> dict:
    try:
        data = event.extra_data or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _str(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().lower()


def _domain(event) -> str | None:
    data = _data(event)
    for key in _DOMAIN_KEYS:
        dom = _str(data.get(key))
        if dom:
            return dom
    return None


def _host(event) -> str | None:
    if isinstance(event.host, str) and event.host.strip():
        return event.host.strip()
    data = _data(event)
    for key in _HOST_KEYS:
        host = _str(data.get(key))
        if host:
            return host
    return None


class DNSAnomalyRule(BaseRule):
    """Verdict-driven or distinct-domain behavioral DNS detection."""

    name = "DNSAnomaly"
    rule_type = "dns_anomaly"
    default_config = {
        "threshold_unique_domains": 50,
        "window_seconds": 300,
    }

    def evaluate(self, ctx: EvaluationContext) -> list[RuleMatch]:
        threshold = int(ctx.rule_config.get("threshold_unique_domains", self.default_config["threshold_unique_domains"]))
        window_seconds = int(ctx.rule_config.get("window_seconds", self.default_config["window_seconds"]))
        windowed = get_time_window(ctx.window_events, window_seconds, ctx.evaluation_time)

        matches: list[RuleMatch] = []

        # Mode 1: explicit malicious verdicts (per domain)
        verdict_groups: dict[str, dict] = {}
        for e in windowed:
            try:
                data = _data(e)
                verdict = _str(data.get("verdict")) or _str(data.get("category"))
                dom = _domain(e)
            except Exception:
                continue
            if verdict is None or verdict not in _MALICIOUS_VERDICTS or dom is None:
                continue
            key = f"dns:{dom}"
            slot = verdict_groups.setdefault(
                key, {"domain": dom, "verdict": verdict, "events": []}
            )
            slot["events"].append(e)
        for key, slot in verdict_groups.items():
            evs = slot["events"]
            matches.append(
                RuleMatch(
                    group_key=key,
                    context={
                        "group_key": key,
                        "rule_type": self.rule_type,
                        "domain": slot["domain"],
                        "verdict": slot["verdict"],
                        "event_count": len(evs),
                        "window_seconds": window_seconds,
                    },
                    evidence_event_ids=sorted(e.id for e in evs),
                    summary=(
                        f"Suspicious DNS verdict for {slot['domain']}: "
                        f"{slot['verdict']} ({len(evs)} events)"
                    ),
                )
            )

        # Mode 2: distinct-domain breadth per host
        host_events: dict[str, list] = {}
        for e in windowed:
            try:
                host = _host(e)
                dom = _domain(e)
            except Exception:
                continue
            if host is None or dom is None:
                continue
            host_events.setdefault(host, []).append(e)
        for host, evs in host_events.items():
            distinct: dict[str, int] = {}
            for e in evs:
                try:
                    dom = _domain(e)
                except Exception:
                    dom = None
                if dom and dom not in distinct:
                    distinct[dom] = e.id
            if len(distinct) >= threshold:
                key = f"dns:{host}"
                # Avoid double-reporting a host already covered by a verdict match
                # for the same host is fine — different group_key, keep both.
                matches.append(
                    RuleMatch(
                        group_key=key,
                        context={
                            "group_key": key,
                            "rule_type": self.rule_type,
                            "host": host,
                            "distinct_domains": len(distinct),
                            "domains": sorted(distinct.keys())[:50],
                            "threshold_unique_domains": threshold,
                            "window_seconds": window_seconds,
                        },
                        evidence_event_ids=sorted(e.id for e in evs),
                        summary=(
                            f"DNS anomaly on {host}: "
                            f"{len(distinct)} distinct domains in {window_seconds}s "
                            f"(threshold {threshold})"
                        ),
                    )
                )
        return matches
