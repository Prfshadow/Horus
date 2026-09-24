"""AccountTakeoverRule — fail-then-success compromise pattern.

Detects: >= fail_threshold failed authentications for one account
followed by a successful login for the SAME account within
window_seconds of the first failure. The success is the signal that
separates possible compromise from ordinary brute force.

Failure: an event with an account field (extra_data.user/username/
account/login) whose level is ERROR, whose extra_data.action (or event)
is in {login_failed, failed_login, auth_failed, auth_failure}, or — for
WARNING/CRITICAL only — whose message carries explicit auth-failure
signals (real auth systems often log failures at WARNING).
Success: an event with the same account whose extra_data.action (or
event) is in {login_success, auth_success, authenticated} or whose
extra_data.status/result is "success" or extra_data.success is True.
Many JSON emitters record the outcome in an `event` field instead of
`action`; that alias is honored identically. Message prose alone never
counts as success — no geo math is attempted.

Grouped by account. Severity from the DetectionRule model (default HIGH).

Default config: fail_threshold=5, window_seconds=300.
"""

from datetime import timedelta, timezone

from app.detection.base import BaseRule, EvaluationContext, RuleMatch
from app.detection.helpers import get_time_window, looks_like_auth_failure

_ACCOUNT_KEYS = ("user", "username", "account", "login")
_FAILURE_ACTIONS = {"login_failed", "failed_login", "auth_failed", "auth_failure", "failure"}
_SUCCESS_ACTIONS = {"login_success", "auth_success", "authenticated", "login succeeded"}


def _data(event) -> dict:
    try:
        data = event.extra_data or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _account(event) -> str | None:
    data = _data(event)
    for key in _ACCOUNT_KEYS:
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def _action(event) -> str | None:
    """Outcome code for the event.

    Reads extra_data.action, with extra_data.event as an alias — many JSON
    emitters record the outcome as `event: login_failed` instead.
    """
    data = _data(event)
    for key in ("action", "event"):
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip().lower()
    return None


def _is_failure(event) -> bool:
    action = _action(event)
    if action is not None and action in _FAILURE_ACTIONS:
        return True
    if (event.level or "").upper() == "ERROR":
        return True
    return looks_like_auth_failure(event)


def _is_success(event) -> bool:
    data = _data(event)
    action = _action(event)
    if action is not None and action in _SUCCESS_ACTIONS:
        return True
    for key in ("status", "result"):
        val = data.get(key)
        if isinstance(val, str) and val.strip().lower() == "success":
            return True
    if data.get("success") is True:
        return True
    return False


def _aware(ts):
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


class AccountTakeoverRule(BaseRule):
    """Fail-then-success pattern per account."""

    name = "AccountTakeover"
    rule_type = "account_takeover"
    default_config = {
        "fail_threshold": 5,
        "window_seconds": 300,
    }

    def evaluate(self, ctx: EvaluationContext) -> list[RuleMatch]:
        fail_threshold = int(ctx.rule_config.get("fail_threshold", self.default_config["fail_threshold"]))
        window_seconds = int(ctx.rule_config.get("window_seconds", self.default_config["window_seconds"]))
        windowed = get_time_window(ctx.window_events, window_seconds, ctx.evaluation_time)

        by_account: dict[str, dict] = {}
        for e in windowed:
            try:
                acct = _account(e)
            except Exception:
                continue
            if acct is None:
                continue
            slot = by_account.setdefault(acct, {"failures": [], "successes": []})
            try:
                if _is_failure(e):
                    slot["failures"].append(e)
                elif _is_success(e):
                    slot["successes"].append(e)
            except Exception:
                continue

        matches: list[RuleMatch] = []
        for acct, slot in by_account.items():
            failures = sorted(slot["failures"], key=lambda e: (_aware(e.timestamp), e.id))
            if len(failures) < fail_threshold:
                continue
            first_fail = _aware(failures[0].timestamp)
            # Success must come at/after the last failure and within the window
            # measured from the first failure.
            last_fail = _aware(failures[-1].timestamp)
            candidates = [
                e for e in slot["successes"]
                if last_fail <= _aware(e.timestamp) <= first_fail + timedelta(seconds=window_seconds)
            ]
            if not candidates:
                continue
            success = sorted(candidates, key=lambda e: (_aware(e.timestamp), e.id))[0]
            ev_ids = sorted([e.id for e in failures] + [success.id])
            key = f"takeover:{acct}"
            matches.append(
                RuleMatch(
                    group_key=key,
                    context={
                        "group_key": key,
                        "rule_type": self.rule_type,
                        "account": acct,
                        "failure_count": len(failures),
                        "fail_threshold": fail_threshold,
                        "success_event_id": success.id,
                        "window_seconds": window_seconds,
                    },
                    evidence_event_ids=ev_ids,
                    summary=(
                        f"Possible account takeover pattern for {acct}: "
                        f"{len(failures)} failures followed by successful login"
                    ),
                )
            )
        return matches
