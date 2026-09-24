"""AuthenticationAnomalyRule — password-spraying pattern detection.

Detects: a single source IP targeting >= threshold_accounts DISTINCT
accounts within window_seconds. Distinct-account breadth (not raw failure
count) separates spraying from a brute force against one account.

An event counts as an authentication attempt only when it carries a
username-ish structured field (extra_data.user/username/account/login).
Events without one are skipped. Any level counts — spray campaigns mix
failures and occasional successes.

Default config: threshold_accounts=5, window_seconds=60.
"""

from app.detection.base import BaseRule, EvaluationContext, RuleMatch
from app.detection.helpers import extract_source_ip, get_time_window

ACCOUNT_KEYS = ("user", "username", "account", "login", "target_user")


def _account(event) -> str | None:
    try:
        data = event.extra_data or {}
        if not isinstance(data, dict):
            return None
        for key in ACCOUNT_KEYS:
            val = data.get(key)
            if val is not None and str(val).strip():
                return str(val).strip()
    except Exception:
        return None
    return None


class AuthenticationAnomalyRule(BaseRule):
    """Distinct-account counting per source IP (spray detection)."""

    name = "AuthenticationAnomaly"
    rule_type = "authentication_anomaly"
    default_config = {
        "threshold_accounts": 5,
        "window_seconds": 60,
        "group_by": "extra_data.ip",
    }

    def evaluate(self, ctx: EvaluationContext) -> list[RuleMatch]:
        threshold = int(ctx.rule_config.get("threshold_accounts", self.default_config["threshold_accounts"]))
        window_seconds = int(ctx.rule_config.get("window_seconds", self.default_config["window_seconds"]))
        group_by = str(ctx.rule_config.get("group_by", self.default_config["group_by"]))

        windowed = get_time_window(ctx.window_events, window_seconds, ctx.evaluation_time)

        groups: dict[str, list] = {}
        for e in windowed:
            ip = extract_source_ip(e)
            acct = _account(e)
            if ip is None or acct is None:
                continue
            groups.setdefault(ip, []).append(e)

        matches: list[RuleMatch] = []
        for ip, evs in groups.items():
            accounts: dict[str, int] = {}
            for e in evs:
                acct = _account(e)
                if acct and acct not in accounts:
                    accounts[acct] = e.id
            if len(accounts) >= threshold:
                ev_ids = sorted(e.id for e in evs)
                shown = sorted(accounts.keys())[:50]
                matches.append(
                    RuleMatch(
                        group_key=f"ip:{ip}",
                        context={
                            "group_key": f"ip:{ip}",
                            "rule_type": self.rule_type,
                            "source_ip": ip,
                            "distinct_accounts": len(accounts),
                            "accounts": shown,
                            "threshold_accounts": threshold,
                            "window_seconds": window_seconds,
                            "group_by": group_by,
                        },
                        evidence_event_ids=ev_ids,
                        summary=(
                            f"Password-spraying pattern detected from {ip}: "
                            f"{len(accounts)} distinct accounts in {window_seconds}s "
                            f"(threshold {threshold})"
                        ),
                    )
                )
        return matches
