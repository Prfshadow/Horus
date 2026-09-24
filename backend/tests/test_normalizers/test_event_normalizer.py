"""Tests for EventNormalizer (M2)."""

from datetime import datetime, timezone
from typing import Any

from app.parsers.base import ParseResult
from app.normalizers.event_normalizer import EventNormalizer, RESERVED_META_KEYS


class TestEventNormalizer:
    """Test EventNormalizer.normalize."""

    def setup_method(self):
        self.normalizer = EventNormalizer(default_source="api-gateway")
        self.ingestion_time = datetime(2026, 9, 14, 10, 0, 5, tzinfo=timezone.utc)

    def test_normalize_parsed_result_with_all_fields(self):
        parse_result = ParseResult(
            success=True,
            timestamp=datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc),
            source="auth-service",
            level="ERROR",
            service="auth",
            host="web-01",
            message="Login failed for user jdoe",
            extra_data={"user": "jdoe", "attempt": 3},
            parser_name="json",
            parse_status="parsed",
        )
        raw_log = '{"timestamp": "2026-09-14T10:00:00Z", "level": "ERROR", "message": "Login failed", "service": "auth", "host": "web-01", "user": "jdoe"}'

        event_create = self.normalizer.normalize(parse_result, raw_log, self.ingestion_time)

        assert event_create.timestamp == datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        assert event_create.source == "auth-service"
        assert event_create.level == "ERROR"
        assert event_create.service == "auth"
        assert event_create.host == "web-01"
        assert event_create.message == "Login failed for user jdoe"
        assert event_create.raw_log == raw_log  # PRESERVED EXACTLY
        assert event_create.extra_data == {
            "user": "jdoe",
            "attempt": 3,
            "timestamp_source": "parsed",
            "parser": "json",
            "parse_status": "parsed",
        }

    def test_normalize_fallback_result_uses_ingestion_time(self):
        parse_result = ParseResult(
            success=True,
            parser_name="text",
            parse_status="fallback",
            message="Something happened",
            level="INFO",
            extra_data={"parser": "text"},
        )
        raw_log = "Something happened"

        event_create = self.normalizer.normalize(parse_result, raw_log, self.ingestion_time)

        # Timestamp falls back to ingestion time
        assert event_create.timestamp == self.ingestion_time
        assert event_create.extra_data["timestamp_source"] == "ingestion_fallback"
        assert event_create.extra_data["parse_status"] == "fallback"
        assert event_create.extra_data["parser"] == "text"
        assert event_create.source == "api-gateway"  # default source
        assert event_create.raw_log == raw_log

    def test_normalize_failed_result(self):
        parse_result = ParseResult(
            success=False,
            parser_name="json",
            parse_status="failed",
            error="Invalid JSON: Expecting value",
            level="ERROR",
            message="Parse failed: Invalid JSON: Expecting value",
            extra_data={"parse_error": "Invalid JSON: Expecting value"},
        )
        raw_log = '{"invalid json'

        event_create = self.normalizer.normalize(parse_result, raw_log, self.ingestion_time)

        assert event_create.timestamp == self.ingestion_time
        assert event_create.level == "ERROR"
        assert event_create.message == "Parse failed: Invalid JSON: Expecting value"
        assert event_create.extra_data["parse_status"] == "failed"
        assert event_create.extra_data["parse_error"] == "Invalid JSON: Expecting value"
        assert event_create.extra_data["timestamp_source"] == "ingestion_fallback"
        assert event_create.raw_log == raw_log

    def test_normalize_source_fallback_chain(self):
        # 1. Parsed source wins
        parse_result = ParseResult(success=True, source="parsed-source", parser_name="json", parse_status="parsed")
        raw_log = '{"source": "parsed-source"}'
        event_create = self.normalizer.normalize(parse_result, raw_log, self.ingestion_time)
        assert event_create.source == "parsed-source"

        # 2. Default source from API param
        parse_result = ParseResult(success=True, source=None, parser_name="text", parse_status="fallback")
        raw_log = "plain text"
        event_create = self.normalizer.normalize(parse_result, raw_log, self.ingestion_time, default_source="api-source")
        assert event_create.source == "api-source"

        # 3. Normalizer default source
        parse_result = ParseResult(success=True, source=None, parser_name="text", parse_status="fallback")
        event_create = self.normalizer.normalize(parse_result, raw_log, self.ingestion_time)
        assert event_create.source == "api-gateway"

    def test_normalize_missing_message_uses_raw_log(self):
        parse_result = ParseResult(success=True, parser_name="json", parse_status="parsed", message=None)
        raw_log = "raw log line"
        event_create = self.normalizer.normalize(parse_result, raw_log, self.ingestion_time)
        assert event_create.message == raw_log

    def test_normalize_empty_extra_data_becomes_none(self):
        parse_result = ParseResult(success=True, extra_data={}, parser_name="json", parse_status="parsed")
        raw_log = '{}'
        event_create = self.normalizer.normalize(parse_result, raw_log, self.ingestion_time)
        # Parser adds timestamp_source, parser, parse_status
        assert event_create.extra_data is not None
        assert "timestamp_source" in event_create.extra_data

    def test_raw_log_preserved_exactly(self):
        """CRITICAL: raw_log must equal input string exactly."""
        test_cases = [
            "simple log",
            '{"json": "object"}',
            "key=value with spaces",
            "unicode: café 🚀",
            "newlines\nand\ttabs",
            "",  # empty
            "   whitespace   ",
        ]

        for raw_log in test_cases:
            parse_result = ParseResult(success=True, parser_name="text", parse_status="fallback")
            event_create = self.normalizer.normalize(parse_result, raw_log, self.ingestion_time)
            assert event_create.raw_log == raw_log, f"Failed for: {repr(raw_log)}"

    def test_normalize_prefixes_metadata_on_collision(self):
        """If extra_data already has reserved keys, HORUS metadata gets prefixed."""
        parse_result = ParseResult(
            success=True,
            timestamp=datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc),
            source="auth-service",
            level="ERROR",
            service="auth",
            host="web-01",
            message="Login failed",
            extra_data={
                "timestamp_source": "user_provided",  # collides
                "parser": "user_parser",  # collides
                "parse_status": "user_status",  # collides
                "ip": "10.0.0.1",
            },
            parser_name="json",
            parse_status="parsed",
        )
        raw_log = '{"timestamp": "2026-09-14T10:00:00Z", "level": "ERROR", "message": "Login failed", "extra_data": {"timestamp_source": "user_provided", "parser": "user_parser", "parse_status": "user_status", "ip": "10.0.0.1"}}'

        event_create = self.normalizer.normalize(parse_result, raw_log, self.ingestion_time)

        # User data preserved at original keys
        assert event_create.extra_data["timestamp_source"] == "user_provided"
        assert event_create.extra_data["parser"] == "user_parser"
        assert event_create.extra_data["parse_status"] == "user_status"
        assert event_create.extra_data["ip"] == "10.0.0.1"

        # HORUS metadata added with prefix
        assert event_create.extra_data["horus_timestamp_source"] == "parsed"
        assert event_create.extra_data["horus_parser"] == "json"
        assert event_create.extra_data["horus_parse_status"] == "parsed"

    def test_normalize_no_collision_uses_original_keys(self):
        """If extra_data has no collision, metadata uses original keys."""
        parse_result = ParseResult(
            success=True,
            timestamp=datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc),
            source="auth-service",
            level="ERROR",
            service="auth",
            host="web-01",
            message="Login failed",
            extra_data={"ip": "10.0.0.1"},
            parser_name="json",
            parse_status="parsed",
        )
        raw_log = '{"timestamp": "2026-09-14T10:00:00Z", "level": "ERROR", "message": "Login failed", "ip": "10.0.0.1"}'

        event_create = self.normalizer.normalize(parse_result, raw_log, self.ingestion_time)

        assert event_create.extra_data["ip"] == "10.0.0.1"
        assert event_create.extra_data["timestamp_source"] == "parsed"
        assert event_create.extra_data["parser"] == "json"
        assert event_create.extra_data["parse_status"] == "parsed"
        assert "horus_timestamp_source" not in event_create.extra_data
        assert "horus_parser" not in event_create.extra_data

    def test_normalize_collision_on_parse_error_key(self):
        """Parse error key collision also gets prefixed."""
        parse_result = ParseResult(
            success=False,
            parser_name="json",
            parse_status="failed",
            error="Invalid JSON",
            level="ERROR",
            message="Parse failed",
            extra_data={"parse_error": "user_error"},
        )
        raw_log = '{"invalid json}'

        event_create = self.normalizer.normalize(parse_result, raw_log, self.ingestion_time)

        assert event_create.extra_data["parse_error"] == "user_error"
        assert event_create.extra_data["horus_parse_error"] == "Invalid JSON"

    def test_reserved_meta_keys_constant_matches_parser(self):
        """RESERVED_META_KEYS in normalizer should match parser's set."""
        # Both should have the same keys
        parser_keys = frozenset({"timestamp_source", "parser", "parse_status", "parse_error"})
        assert RESERVED_META_KEYS == parser_keys