"""SQLInjectionRule — structured SQL-injection attempt detection.

Detects: events carrying explicit SQL-injection telemetry or strong,
controlled payload signatures. Bare words like "select" or "union" NEVER
fire this rule on their own.

Signal priority (first hit wins per event):
  1. Structured: extra_data.attack_type in {sqli, sql_injection,
     sql-injection} (case-insensitive).
  2. Structured: extra_data.rule names a SQLi rule — contains "sql" plus
     ("inject" or a 942xxx CRS SQL-injection family id).
  3. Payload: strong regexes against extra_data.payload/parameter/query/
     path (see _PAYLOAD_PATTERNS).
  4. Message fallback: only the strongest patterns (union-select,
     information_schema, drop-table) against the message text.

Each (source, indicator) group yields one match; evidence is every
matching event in the group. Severity comes from the DetectionRule model
(default HIGH).

Default config: window_seconds=300.
"""

import re

from app.detection.base import BaseRule, EvaluationContext, RuleMatch
from app.detection.helpers import extract_source_ip, get_time_window

_ATTACK_TYPES = {"sqli", "sql_injection", "sql-injection", "sql injection"}
_CRS_SQLI_RE = re.compile(r"942\d{3}")

_PAYLOAD_PATTERNS = [
    re.compile(r"union\s+(all\s+)?select", re.IGNORECASE),
    re.compile(r"information_schema", re.IGNORECASE),
    re.compile(r";\s*drop\s+table", re.IGNORECASE),
    re.compile(r"'\s*or\s+'1'\s*=\s*'1", re.IGNORECASE),
    re.compile(r'"\s*or\s+"1"\s*=\s*"1', re.IGNORECASE),
    re.compile(r"sleep\s*\(\s*\d+\s*\)", re.IGNORECASE),
    re.compile(r"benchmark\s*\(", re.IGNORECASE),
    re.compile(r"@@version|@@datadir", re.IGNORECASE),
    re.compile(r"load_file\s*\(", re.IGNORECASE),
    re.compile(r"into\s+(outfile|dumpfile)", re.IGNORECASE),
]

# Message fallback is deliberately narrower than payload matching.
_MESSAGE_PATTERNS = [
    re.compile(r"union\s+(all\s+)?select", re.IGNORECASE),
    re.compile(r"information_schema", re.IGNORECASE),
    re.compile(r";\s*drop\s+table", re.IGNORECASE),
]

_PAYLOAD_KEYS = ("payload", "parameter", "query", "query_string", "path", "uri", "body")


def _data(event) -> dict:
    try:
        data = event.extra_data or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _indicator(event) -> tuple[str, str] | None:
    """Return (indicator, detail) if the event shows SQLi, else None."""
    data = _data(event)

    attack_type = data.get("attack_type")
    if isinstance(attack_type, str) and attack_type.strip().lower() in _ATTACK_TYPES:
        return ("structured:attack_type", attack_type.strip()[:100])

    rule = data.get("rule") or data.get("security_rule")
    if isinstance(rule, str):
        lowered = rule.strip().lower()
        if "sql" in lowered and ("inject" in lowered or _CRS_SQLI_RE.search(rule)):
            return ("structured:rule", rule.strip()[:100])

    for key in _PAYLOAD_KEYS:
        val = data.get(key)
        if isinstance(val, str):
            for pat in _PAYLOAD_PATTERNS:
                if pat.search(val):
                    return ("payload-signature", pat.pattern[:80])

    message = event.message if isinstance(event.message, str) else ""
    for pat in _MESSAGE_PATTERNS:
        if pat.search(message):
            return ("message-signature", pat.pattern[:80])
    return None


class SQLInjectionRule(BaseRule):
    """Per-event SQLi telemetry/signature detection, grouped by source."""

    name = "SQLInjection"
    rule_type = "sql_injection"
    default_config = {
        "window_seconds": 300,
    }

    def evaluate(self, ctx: EvaluationContext) -> list[RuleMatch]:
        window_seconds = int(ctx.rule_config.get("window_seconds", self.default_config["window_seconds"]))
        windowed = get_time_window(ctx.window_events, window_seconds, ctx.evaluation_time)

        groups: dict[str, dict] = {}
        for e in windowed:
            try:
                found = _indicator(e)
            except Exception:
                continue
            if found is None:
                continue
            indicator, detail = found
            ip = extract_source_ip(e) or (e.host or "unknown")
            key = f"sqli:{ip}:{indicator}"
            slot = groups.setdefault(key, {"ip": ip, "indicator": indicator, "detail": detail, "events": []})
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
                        "source_ip": slot["ip"],
                        "indicator": slot["indicator"],
                        "detail": slot["detail"],
                        "event_count": len(evs),
                        "window_seconds": window_seconds,
                    },
                    evidence_event_ids=ev_ids,
                    summary=(
                        f"SQL injection attempt detected from {slot['ip']}: "
                        f"{slot['indicator']} ({len(evs)} events)"
                    ),
                )
            )
        return matches
