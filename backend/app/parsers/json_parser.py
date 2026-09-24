"""JSON log parser (M2)."""

import json
from typing import Any

from app.parsers.base import BaseParser, ParseResult, create_failed_result


# Reserved metadata keys that HORUS injects during normalization.
# If user data contains these, we preserve user data and add a suffix to metadata.
RESERVED_META_KEYS = frozenset({
    "timestamp_source",
    "parser",
    "parse_status",
    "parse_error",
})


class JSONParser(BaseParser):
    """Parser for structured JSON log lines.

    Expected format: {"timestamp": "...", "level": "...", "message": "...", ...}
    All fields optional; unknown fields go to extra_data.

    If the JSON contains an "extra_data" key, its contents are MERGED into
    the top-level extra_data (not nested). This preserves user-provided
    structured fields directly accessible in Event.extra_data.
    """

    @property
    def name(self) -> str:
        return "json"

    def can_parse(self, raw_log: str) -> bool:
        """Quick check: starts with { after stripping whitespace."""
        stripped = raw_log.lstrip()
        return stripped.startswith("{") and stripped.endswith("}")

    def parse(self, raw_log: str) -> ParseResult:
        """Parse JSON log line."""
        try:
            data = json.loads(raw_log)
        except json.JSONDecodeError as e:
            return create_failed_result(self.name, f"Invalid JSON: {e}", raw_log)

        if not isinstance(data, dict):
            return create_failed_result(self.name, "JSON root must be an object", raw_log)

        # Extract known fields
        timestamp = self._parse_timestamp(data.get("timestamp") or data.get("@timestamp") or data.get("time"))
        level = self._normalize_level(data.get("level") or data.get("severity") or data.get("loglevel"))
        message = data.get("message") or data.get("msg") or data.get("log")
        # source: only from explicit source/logger fields, NOT from service
        source = data.get("source") or data.get("logger")
        service = data.get("service") or data.get("service_name")
        host = data.get("host") or data.get("hostname") or data.get("machine")

        # Everything else goes to extra_data, with special handling for "extra_data" key
        known_keys = {"timestamp", "@timestamp", "time", "level", "severity", "loglevel",
                      "message", "msg", "log", "source", "logger", "service", "service_name",
                      "host", "hostname", "machine"}
        extra = {}
        for k, v in data.items():
            if k in known_keys:
                continue
            if k == "extra_data" and isinstance(v, dict):
                # MERGE user-provided extra_data fields directly (flatten)
                for ek, ev in v.items():
                    if ek in RESERVED_META_KEYS:
                        # Collision: user data has a reserved key.
                        # Preserve user data at original key; we'll add HORUS metadata
                        # with a prefix later in the normalizer.
                        extra[ek] = ev
                    else:
                        extra[ek] = ev
            else:
                extra[k] = v

        # If no message field, synthesize from remaining data
        if message is None:
            if extra:
                message = " | ".join(f"{k}={v}" for k, v in extra.items())
            else:
                message = "JSON log (no message field)"

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