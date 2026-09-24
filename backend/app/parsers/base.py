"""Base parser interface and parse result (M2)."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class ParseResult:
    """Result of parsing a raw log line.

    Attributes:
        success: Whether parsing succeeded (True) or failed (False).
        timestamp: Extracted event timestamp (UTC), if available.
        source: Log source identifier (e.g., "nginx", "auth-service").
        level: Normalized severity (DEBUG/INFO/WARNING/ERROR/CRITICAL).
        service: Logical service name.
        host: Origin host/container.
        message: Human-readable message.
        extra_data: Additional structured fields not mapped to fixed columns (None if empty).
        error: Error message if parsing failed.
        parser_name: Name of the parser that produced this result.
        parse_status: "parsed" | "fallback" | "failed"
    """
    success: bool
    timestamp: Optional[datetime] = None
    source: Optional[str] = None
    level: Optional[str] = None
    service: Optional[str] = None
    host: Optional[str] = None
    message: Optional[str] = None
    extra_data: Optional[dict] = None
    error: Optional[str] = None
    parser_name: str = "unknown"
    parse_status: str = "parsed"  # "parsed" | "fallback" | "failed"

    def __post_init__(self):
        if self.parse_status not in ("parsed", "fallback", "failed"):
            self.parse_status = "parsed"


class BaseParser(ABC):
    """Abstract base class for log parsers.

    Each parser implements:
    - can_parse(): Fast heuristic to check if this parser might handle the log
    - parse(): Full parsing logic, returns ParseResult (never raises)
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique parser identifier (e.g., 'json', 'keyvalue', 'text')."""
        pass

    @abstractmethod
    def can_parse(self, raw_log: str) -> bool:
        """Fast check if this parser can handle the log.

        Should be lightweight (no full parse). Used by registry for detection.
        """
        pass

    @abstractmethod
    def parse(self, raw_log: str) -> ParseResult:
        """Parse a raw log line.

        Never raises exceptions. Returns ParseResult with success=False on failure.
        """
        pass

    # Short aliases used across JSON, key=value, and syslog dialects.
    LEVEL_ALIASES = {"WARN": "WARNING", "FATAL": "CRITICAL", "ERR": "ERROR"}

    def _normalize_level(self, level: Optional[str]) -> str:
        """Normalize severity level to standard values."""
        if level is None:
            return "INFO"
        normalized = level.upper().strip()
        normalized = self.LEVEL_ALIASES.get(normalized, normalized)
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        return normalized if normalized in valid_levels else "INFO"

    def _parse_timestamp(self, value: Optional[str]) -> Optional[datetime]:
        """Parse timestamp string to timezone-aware UTC datetime.

        Supports ISO 8601 formats commonly found in logs.
        Returns None if parsing fails.
        """
        if not value:
            return None
        try:
            # Handle common timestamp formats
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except (ValueError, AttributeError):
            return None


def create_failed_result(parser_name: str, error: str, raw_log: str) -> ParseResult:
    """Factory for failed parse results."""
    return ParseResult(
        success=False,
        error=error,
        parser_name=parser_name,
        parse_status="failed",
        message=f"Parse failed: {error}",
        level="ERROR",
        extra_data={"parse_error": error, "raw_log": raw_log},
    )


def create_fallback_result(parser_name: str, raw_log: str, message: Optional[str] = None) -> ParseResult:
    """Factory for fallback (unstructured) parse results."""
    return ParseResult(
        success=True,
        parser_name=parser_name,
        parse_status="fallback",
        message=message or raw_log,
        level="INFO",
        extra_data={"parser": parser_name},
    )