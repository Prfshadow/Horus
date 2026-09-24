"""Event normalizer: converts ParseResult to EventCreate (M2)."""

from datetime import datetime, timezone
from typing import Any, Optional

from app.parsers.base import ParseResult
from app.schemas.event import EventCreate

# Reserved metadata keys that HORUS injects during normalization.
# If user data already contains these, we prefix with "horus_".
RESERVED_META_KEYS = frozenset({
    "timestamp_source",
    "parser",
    "parse_status",
    "parse_error",
})


class EventNormalizer:
    """Normalizes ParseResult into a validated EventCreate schema.

    Handles:
    - Timestamp fallback (ingestion time if parser couldn't extract)
    - Source fallback (default from API if parser couldn't extract)
    - Recording timestamp source in extra_data
    - Preserving raw_log verbatim
    """

    def __init__(self, default_source: str = "unknown"):
        self.default_source = default_source

    def _add_metadata(self, extra_data: dict, key: str, value: Any) -> None:
        """Add metadata to extra_data, prefixing if user data already occupies the key."""
        if key in extra_data:
            # User data already has this key - prefix HORUS metadata
            extra_data[f"horus_{key}"] = value
        else:
            extra_data[key] = value

    def normalize(
        self,
        parse_result: ParseResult,
        raw_log: str,
        ingestion_time: datetime,
        default_source: Optional[str] = None,
    ) -> EventCreate:
        """Convert ParseResult to EventCreate.

        Args:
            parse_result: Result from parser
            raw_log: Original raw log string (must be preserved exactly)
            ingestion_time: Server ingestion timestamp (UTC)
            default_source: Override default source (e.g., from API header)

        Returns:
            Validated EventCreate ready for database storage
        """
        source = parse_result.source or default_source or self.default_source

        # Determine timestamp
        timestamp = parse_result.timestamp
        timestamp_source = "parsed"
        if timestamp is None:
            timestamp = ingestion_time
            timestamp_source = "ingestion_fallback"

        # Build extra_data with parse metadata
        extra_data = dict(parse_result.extra_data) if parse_result.extra_data else {}

        # Add HORUS metadata with collision handling
        self._add_metadata(extra_data, "timestamp_source", timestamp_source)
        self._add_metadata(extra_data, "parser", parse_result.parser_name)
        self._add_metadata(extra_data, "parse_status", parse_result.parse_status)

        if parse_result.parse_status == "failed":
            self._add_metadata(extra_data, "parse_error", parse_result.error)

        # For parse failures, level is already ERROR from parser
        # For successful parses, use parsed level (normalized by parser)
        level = parse_result.level or "INFO"

        # Message must be non-empty (EventCreate requires min_length=1)
        # Priority: parsed message > raw_log > placeholder
        message = parse_result.message or raw_log or "(empty log line)"

        return EventCreate(
            timestamp=timestamp,
            source=source,
            level=level,
            service=parse_result.service,
            host=parse_result.host,
            message=message,
            raw_log=raw_log,  # PRESERVED EXACTLY AS RECEIVED
            extra_data=extra_data if extra_data else None,
        )