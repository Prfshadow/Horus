"""Key=Value log parser (M2).

Parses logs in format: key1=value1 key2="quoted value" key3=value3
Handles quoted values with spaces and escaped quotes.
"""

import re
from typing import Any

from app.parsers.base import BaseParser, ParseResult, create_failed_result


class KeyValueParser(BaseParser):
    """Parser for key=value pair log lines.

    Examples:
        timestamp=2026-09-14T10:00:00Z level=ERROR message="Login failed" user=jdoe
        user="john doe" action=login status=success ip=10.0.0.1
    """

    # Regex to match key=value pairs, handling quoted values with escaped quotes
    # Matches: key=value, key="value with spaces", key='single quoted', key="escaped \" quote"
    KV_PATTERN = re.compile(
        r'''(\w+)=          # key=
            (?:             # value:
                "((?:[^"\\]|\\.)*)"  # double-quoted (handles escaped)
                |
                '((?:[^'\\]|\\.)*)'  # single-quoted
                |
                (\S+)       # unquoted (no whitespace)
            )''',
        re.VERBOSE
    )

    @property
    def name(self) -> str:
        return "keyvalue"

    def can_parse(self, raw_log: str) -> bool:
        """Quick check: contains at least one key=value pattern."""
        return "=" in raw_log and not raw_log.lstrip().startswith("{")

    def parse(self, raw_log: str) -> ParseResult:
        """Parse key=value log line."""
        pairs = self._extract_pairs(raw_log)

        if not pairs:
            return create_failed_result(self.name, "No key=value pairs found", raw_log)

        # Extract known fields
        timestamp = self._parse_timestamp(pairs.get("timestamp") or pairs.get("@timestamp") or pairs.get("time"))
        level = self._normalize_level(pairs.get("level") or pairs.get("severity") or pairs.get("loglevel"))
        message = pairs.get("message") or pairs.get("msg") or pairs.get("log")
        # source: only from explicit source/logger fields, NOT from service
        source = pairs.get("source") or pairs.get("logger")
        service = pairs.get("service") or pairs.get("service_name")
        host = pairs.get("host") or pairs.get("hostname") or pairs.get("machine")

        # Everything else goes to extra_data
        known_keys = {"timestamp", "@timestamp", "time", "level", "severity", "loglevel",
                      "message", "msg", "log", "source", "logger", "service", "service_name",
                      "host", "hostname", "machine"}
        extra = {k: v for k, v in pairs.items() if k not in known_keys}

        # If no message field, synthesize from remaining data
        if message is None:
            if extra:
                message = " | ".join(f"{k}={v}" for k, v in extra.items())
            else:
                message = "Key=value log (no message field)"

        return ParseResult(
            success=True,
            timestamp=timestamp,
            source=source,
            level=level,
            service=service,
            host=host,
            message=message,
            extra_data=extra if extra else None,
            parser_name=self.name,
            parse_status="parsed",
        )

    def _extract_pairs(self, raw_log: str) -> dict[str, str]:
        """Extract key=value pairs from log line.

        Returns dict of key -> unquoted value.
        Handles escaped quotes in quoted values.
        """
        return extract_kv_pairs(raw_log)


def extract_kv_pairs(raw_log: str) -> dict[str, str]:
    """Extract key=value pairs from arbitrary text.

    Shared helper so other parsers (e.g. syslog, whose message tail may
    carry embedded pairs) reuse the exact same extraction semantics.
    """
    pairs = {}
    for match in KeyValueParser.KV_PATTERN.finditer(raw_log):
        key = match.group(1)
        # Value is in group 2 (double-quoted), 3 (single-quoted), or 4 (unquoted)
        value = match.group(2) or match.group(3) or match.group(4)
        if value is not None:
            # Unescape quotes in quoted values
            value = value.replace('\\"', '"').replace("\\'", "'")
            pairs[key] = value
    return pairs