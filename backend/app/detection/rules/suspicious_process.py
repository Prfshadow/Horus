"""SuspiciousProcessRule — suspicious process-execution detection.

Detects: security telemetry describing process execution that is
explicitly flagged OR matches controlled suspicious combinations. A bare
"powershell.exe" (or any shell) NEVER fires this rule on its own.

Triggers (any suffices, all case-insensitive):
  1. Explicit verdict: extra_data.verdict/execution_type in
     {malicious, suspicious, blocked} with a process present.
  2. Encoded execution: command contains an encoded-execution marker
     (-EncodedCommand, FromBase64String, --encode) AND the parent process
     is unusual (office/script-host/browser) OR the command contains a
     known adversarial keyword (mimikatz, downloadstring, invoke-,
     powershell -w hidden, etc.).
  3. Office-spawned shell: parent in {winword, excel, powerpnt, outlook,
     wscript, cscript, mshta} AND child in {powershell, cmd, wscript,
     cscript, mshta, rundll32, pwsh}.
  4. LOLBin-with-download: process in {certutil, bitsadmin, mshta,
     rundll32, regsvr32} AND command contains a download/URL keyword
     (http, urlcache, /transfer, .ps1, .vbs, .js).

Grouped by (host-or-user, process). Severity from the DetectionRule
model (default HIGH).

Default config: window_seconds=300.
"""

import re

from app.detection.base import BaseRule, EvaluationContext, RuleMatch
from app.detection.helpers import get_time_window

_EXPLICIT_VERDICTS = {"malicious", "suspicious", "blocked"}

_ENCODED_MARKERS = [
    "-encodedcommand",
    "-enc ",
    "-enc=",
    "frombase64string",
    "--encode",
    "-e ",
]

_ADVERSARIAL_KEYWORDS = [
    "mimikatz",
    "downloadstring",
    "invoke-mimikatz",
    "invoke-shellcode",
    "powersploit",
    "cobaltstrike",
    "meterpreter",
    "-w hidden",
    "-windowstyle hidden",
    "bypass",
    "unrestricted",
]

_OFFICE_PARENTS = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "iexplore.exe",
    "chrome.exe",
    "firefox.exe",
}

_SHELL_CHILDREN = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
}

_LOLBIN_DOWNLOAD = {
    "certutil.exe": ["urlcache", "http"],
    "bitsadmin.exe": ["/transfer", "http"],
    "mshta.exe": ["http", ".hta"],
    "rundll32.exe": ["http", ".dll,"],
    "regsvr32.exe": ["http", "/s /u /i:"],
}


def _data(event) -> dict:
    try:
        data = event.extra_data or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _lower(value: object) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


def _basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1].strip().lower()


def _indicator(event) -> tuple[str, str] | None:
    data = _data(event)
    process = _lower(data.get("process"))
    parent = _lower(data.get("parent_process"))
    command = _lower(data.get("command"))
    if not process:
        return None

    for key in ("verdict", "execution_type"):
        verdict = _lower(data.get(key))
        if verdict in _EXPLICIT_VERDICTS:
            return ("explicit-verdict", f"{key}={verdict}")

    parent_base = _basename(parent) if parent else ""
    process_base = _basename(process)

    if any(m in command for m in _ENCODED_MARKERS):
        if parent_base in _OFFICE_PARENTS or any(k in command for k in _ADVERSARIAL_KEYWORDS):
            return ("encoded-execution", f"{process_base} via {parent_base or 'unknown parent'}")

    if parent_base in _OFFICE_PARENTS and process_base in _SHELL_CHILDREN:
        return ("office-spawned-shell", f"{process_base} spawned by {parent_base}")

    keywords = _LOLBIN_DOWNLOAD.get(process_base)
    if keywords and any(k in command for k in keywords):
        return ("lolbin-download", f"{process_base} download pattern")

    return None


def _subject(event) -> str | None:
    data = _data(event)
    host = event.host
    if isinstance(host, str) and host.strip():
        return host.strip()
    for key in ("host", "hostname", "user", "username"):
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


class SuspiciousProcessRule(BaseRule):
    """Controlled process-execution telemetry detection."""

    name = "SuspiciousProcess"
    rule_type = "suspicious_process"
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
                subject = _subject(e)
            except Exception:
                continue
            if found is None or subject is None:
                continue
            indicator, detail = found
            data = _data(e)
            proc = _lower(data.get("process")) or "unknown"
            key = f"susp:{subject}:{indicator}"
            slot = groups.setdefault(
                key, {"subject": subject, "process": proc, "indicator": indicator, "detail": detail, "events": []}
            )
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
                        "subject": slot["subject"],
                        "process": slot["process"],
                        "indicator": slot["indicator"],
                        "detail": slot["detail"],
                        "event_count": len(evs),
                        "window_seconds": window_seconds,
                    },
                    evidence_event_ids=ev_ids,
                    summary=(
                        f"Suspicious process execution on {slot['subject']}: "
                        f"{slot['detail']} ({len(evs)} events)"
                    ),
                )
            )
        return matches
