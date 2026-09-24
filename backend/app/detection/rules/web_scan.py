"""WebScanRule — one source requesting many distinct suspicious endpoints.

Detects: a single source IP requesting >= threshold_paths DISTINCT
suspicious paths within window_seconds. Breadth (distinct paths) is the
signal; a lone /admin hit never fires.

A path is suspicious when it exactly matches a configured suspicious path
(case-insensitive, query string stripped) or starts with a configured
suspicious prefix. Structured extra_data.path is required — plain message
text is never inspected, so benign prose cannot trigger this rule.

Default config: threshold_paths=8, window_seconds=60.
"""

from app.detection.base import BaseRule, EvaluationContext, RuleMatch
from app.detection.helpers import extract_source_ip, get_time_window

DEFAULT_SUSPICIOUS_PATHS = [
    "/admin",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/.env",
    "/.git/config",
    "/config",
    "/backup",
    "/login",
    "/api/debug",
    "/server-status",
    "/server-info",
    "/.svn/entries",
    "/.aws/credentials",
    "/actuator",
    "/debug",
]

DEFAULT_SUSPICIOUS_PREFIXES = [
    "/.git/",
    "/.svn/",
    "/.env",
    "/wp-",
    "/phpmyadmin",
    "/server-",
    "/api/debug",
    "/backup",
    "/config",
    "/debug",
    "/actuator",
]


def _normalize_path(raw: object) -> str | None:
    if not isinstance(raw, str):
        return None
    path = raw.strip().split("?", 1)[0].split("#", 1)[0].strip()
    if not path.startswith("/"):
        return None
    return path.lower()


def _is_suspicious(path: str, paths: list, prefixes: list) -> bool:
    if path in paths:
        return True
    return any(path.startswith(p) for p in prefixes)


class WebScanRule(BaseRule):
    """Distinct suspicious-endpoint counting per source IP."""

    name = "WebScan"
    rule_type = "web_scan"
    default_config = {
        "threshold_paths": 8,
        "window_seconds": 60,
        "group_by": "extra_data.ip",
        "suspicious_paths": DEFAULT_SUSPICIOUS_PATHS,
        "suspicious_prefixes": DEFAULT_SUSPICIOUS_PREFIXES,
    }

    def evaluate(self, ctx: EvaluationContext) -> list[RuleMatch]:
        threshold = int(ctx.rule_config.get("threshold_paths", self.default_config["threshold_paths"]))
        window_seconds = int(ctx.rule_config.get("window_seconds", self.default_config["window_seconds"]))
        group_by = str(ctx.rule_config.get("group_by", self.default_config["group_by"]))
        raw_paths = ctx.rule_config.get("suspicious_paths", self.default_config["suspicious_paths"])
        raw_prefixes = ctx.rule_config.get("suspicious_prefixes", self.default_config["suspicious_prefixes"])
        paths = [p.lower() for p in raw_paths] if isinstance(raw_paths, list) else DEFAULT_SUSPICIOUS_PATHS
        prefixes = [p.lower() for p in raw_prefixes] if isinstance(raw_prefixes, list) else DEFAULT_SUSPICIOUS_PREFIXES

        windowed = get_time_window(ctx.window_events, window_seconds, ctx.evaluation_time)

        groups: dict[str, list] = {}
        for e in windowed:
            ip = extract_source_ip(e)
            if ip is None:
                continue
            try:
                data = e.extra_data or {}
                if not isinstance(data, dict):
                    continue
                norm = _normalize_path(data.get("path"))
            except Exception:
                continue
            if norm is None or not _is_suspicious(norm, paths, prefixes):
                continue
            groups.setdefault(ip, []).append(e)

        matches: list[RuleMatch] = []
        for ip, evs in groups.items():
            distinct: dict[str, int] = {}
            for e in evs:
                try:
                    norm = _normalize_path((e.extra_data or {}).get("path"))
                except Exception:
                    norm = None
                if norm:
                    distinct.setdefault(norm, e.id)
            if len(distinct) >= threshold:
                ev_ids = sorted(e.id for e in evs)
                shown = sorted(distinct.keys())[:50]
                matches.append(
                    RuleMatch(
                        group_key=f"ip:{ip}",
                        context={
                            "group_key": f"ip:{ip}",
                            "rule_type": self.rule_type,
                            "source_ip": ip,
                            "distinct_paths": len(distinct),
                            "paths": shown,
                            "threshold_paths": threshold,
                            "window_seconds": window_seconds,
                            "group_by": group_by,
                        },
                        evidence_event_ids=ev_ids,
                        summary=(
                            f"Web scan pattern detected from {ip}: "
                            f"{len(distinct)} distinct suspicious paths in {window_seconds}s "
                            f"(threshold {threshold})"
                        ),
                    )
                )
        return matches
