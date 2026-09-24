"""XSSAttemptRule — structured cross-site-scripting attempt detection.

Detects: events carrying explicit XSS telemetry or strong, controlled
payload signatures. The bare word "script" (or any ordinary prose) NEVER
fires this rule.

Signal priority (first hit wins per event):
  1. Structured: extra_data.attack_type in {xss, cross-site-scripting,
     cross_site_scripting} (case-insensitive).
  2. Structured: extra_data.rule/security_rule containing "xss".
  3. Payload: strong regexes against extra_data.payload/parameter/query/
     path (see _PAYLOAD_PATTERNS).

Each (source, indicator) group yields one match; evidence is every
matching event in the group. Severity comes from the DetectionRule model
(default HIGH).

Default config: window_seconds=300.
"""

import re

from app.detection.base import BaseRule, EvaluationContext, RuleMatch
from app.detection.helpers import extract_source_ip, get_time_window

_ATTACK_TYPES = {"xss", "cross-site-scripting", "cross_site_scripting", "cross site scripting"}

_PAYLOAD_PATTERNS = [
    re.compile(r"<\s*script[\s>]", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"<\s*img[^>]+onerror\s*=", re.IGNORECASE),
    re.compile(r"<\s*svg[^>]+onload\s*=", re.IGNORECASE),
    re.compile(r"<\s*body[^>]+onload\s*=", re.IGNORECASE),
    re.compile(r"on\w+\s*=\s*[\"']", re.IGNORECASE),
    re.compile(r"%3[cC]\s*script", re.IGNORECASE),
    re.compile(r"&lt;\s*script", re.IGNORECASE),
    re.compile(r"document\s*\.\s*cookie", re.IGNORECASE),
]

_PAYLOAD_KEYS = ("payload", "parameter", "query", "query_string", "path", "uri", "body")


def _data(event) -> dict:
    try:
        data = event.extra_data or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _indicator(event) -> tuple[str, str] | None:
    data = _data(event)

    attack_type = data.get("attack_type")
    if isinstance(attack_type, str) and attack_type.strip().lower() in _ATTACK_TYPES:
        return ("structured:attack_type", attack_type.strip()[:100])

    for key in ("rule", "security_rule"):
        rule = data.get(key)
        if isinstance(rule, str) and "xss" in rule.strip().lower():
            return ("structured:rule", rule.strip()[:100])

    for key in _PAYLOAD_KEYS:
        val = data.get(key)
        if isinstance(val, str):
            for pat in _PAYLOAD_PATTERNS:
                if pat.search(val):
                    return ("payload-signature", pat.pattern[:80])
    return None


class XSSAttemptRule(BaseRule):
    """Per-event XSS telemetry/signature detection, grouped by source."""

    name = "XSSAttempt"
    rule_type = "xss_attempt"
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
            key = f"xss:{ip}:{indicator}"
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
                        f"Cross-site scripting attempt detected from {slot['ip']}: "
                        f"{slot['indicator']} ({len(evs)} events)"
                    ),
                )
            )
        return matches
