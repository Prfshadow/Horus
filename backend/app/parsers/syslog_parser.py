"""Syslog-style prefixed log parser (M2).

Handles the extremely common line family:

    2026-09-24 13:43:27 WARN  auth.service     Failed login attempt username=admin ip=10.10.5.44
    2026-09-24T14:21:23Z | ERROR | auth | Login failed | user=admin | source=10.20.30.44
    [2026-09-24 14:21:26] WARN authentication: account=admin status=LOCKED
    2026-09-24T14:23:18Z [INFO] worker job_id=8821 status=started

i.e. `<timestamp> <LEVEL> <service> <free-text message, often with
embedded key=value pairs>`, with optional pipe separators, square
brackets around the timestamp and/or level, and a trailing colon on the
service token. Without this parser, such lines fall through to the
key=value parser (which loses the leading timestamp/level/service) or to
the text fallback (which loses everything structural).
"""

import re

from app.parsers.base import BaseParser, ParseResult, create_failed_result
from app.parsers.keyvalue_parser import extract_kv_pairs


def _looks_like_ip(value: str) -> bool:
    """True for IPv4 literals (and coloned hex, i.e. IPv6)."""
    v = value.strip()
    parts = v.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return v.count(":") >= 2 and all(
        c in "0123456789abcdefABCDEF:.%/" for c in v
    )


# Alternate keys that, when holding an IP-shaped value, identify the
# source host — aliased to `ip` so grouping/correlation keep working.
IP_ALIAS_KEYS = ("src", "source_ip", "src_ip", "client_ip", "remote_addr", "source")


class SyslogParser(BaseParser):
    """Parser for `TIMESTAMP LEVEL service message...` log lines."""

    # Leading "2026-09-24 13:43:27 WARN" (or ISO "2026-09-24T13:43:27Z WARN",
    # bracketed "[2026-09-24 13:43:27] WARN", "2026-09-24T13:43:27Z [INFO]",
    # or pipe-separated "2026-09-24T13:43:27Z | ERROR | ...").
    PREFIX_RE = re.compile(
        r"^\[?\d{4}-\d{1,2}-\d{1,2}[T ]\d{1,2}:\d{2}:\d{2}"
        r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\]?"
        r"\s*(?:\|\s*)?\[?(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)\b",
        re.IGNORECASE,
    )

    # Short level aliases mapped onto the canonical HORUS levels.
    LEVEL_ALIASES = {"WARN": "WARNING", "FATAL": "CRITICAL"}

    @property
    def name(self) -> str:
        return "syslog"

    def can_parse(self, raw_log: str) -> bool:
        """Fast check: leading timestamp + level token (pipes/brackets tolerated)."""
        return self.PREFIX_RE.match(raw_log.strip()) is not None

    def parse(self, raw_log: str) -> ParseResult:
        """Parse a prefixed syslog-style line. Never raises."""
        text = raw_log.strip()
        if not text:
            return create_failed_result(self.name, "Empty log line", raw_log)

        # "|" only ever separates prefix fields; drop bare separator tokens
        # (message text keeps its other characters verbatim).
        tokens = [t for t in text.split() if t != "|"]
        try:
            # Timestamp is either "date time" (two tokens) or a single ISO token.
            # Strip brackets that may wrap either form ("[2026-09-24 14:21:26]").
            t0 = tokens[0].strip("[]") if len(tokens) > 0 else ""
            t1 = tokens[1].strip("[]") if len(tokens) > 1 else ""
            timestamp = self._parse_timestamp(f"{t0} {t1}".strip())
            rest_index = 2
            if timestamp is None:
                timestamp = self._parse_timestamp(t0)
                rest_index = 1
            if timestamp is None:
                return create_failed_result(self.name, "Unparseable timestamp prefix", raw_log)

            level_token = tokens[rest_index].strip("[]").upper()
            level_token = self.LEVEL_ALIASES.get(level_token, level_token)
            level = self._normalize_level(level_token)
            # _normalize_level falls back to INFO for unknown tokens; since
            # can_parse already validated the token, an INFO here for a
            # non-INFO token means something inconsistent — fail honestly.
            if level == "INFO" and level_token != "INFO":
                return create_failed_result(self.name, f"Unknown level token: {tokens[rest_index]}", raw_log)

            service = None
            if len(tokens) > rest_index + 1:
                # A trailing colon is punctuation ("authentication:"), not name.
                service = tokens[rest_index + 1].rstrip(":") or None
            message = " ".join(tokens[rest_index + 2:]) if len(tokens) > rest_index + 2 else ""
            if not message:
                message = "(empty log line)"

            # The free-text tail often carries embedded key=value pairs
            # (username=admin ip=10.10.5.44) — harvest them as extra_data.
            extra = extract_kv_pairs(message)
            # ...and make sure the source host is findable as `ip` even when
            # the log calls the key src/source_ip/client_ip/... (or a bare
            # IP-shaped `source=`), so grouping and correlation keep working.
            if "ip" not in extra:
                for key in IP_ALIAS_KEYS:
                    val = extra.get(key)
                    if isinstance(val, str) and _looks_like_ip(val):
                        extra["ip"] = val.strip()
                        break

            return ParseResult(
                success=True,
                timestamp=timestamp,
                source=service,
                level=level,
                service=service,
                host=None,
                message=message,
                extra_data=extra if extra else None,
                parser_name=self.name,
                parse_status="parsed",
            )
        except (IndexError, AttributeError) as e:
            return create_failed_result(self.name, f"Malformed syslog prefix: {e}", raw_log)
