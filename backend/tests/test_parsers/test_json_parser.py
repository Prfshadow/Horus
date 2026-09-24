"""Tests for JSON parser (M2)."""

import json
from datetime import datetime, timezone

from app.parsers.json_parser import JSONParser, RESERVED_META_KEYS
from app.parsers.base import ParseResult


class TestJSONParser:
    """Test JSONParser.can_parse and JSONParser.parse."""

    def setup_method(self):
        self.parser = JSONParser()

    def test_can_parse_valid_json(self):
        assert self.parser.can_parse('{"message": "hello"}')
        assert self.parser.can_parse('  {"level": "INFO"}')
        assert self.parser.can_parse('\t{"timestamp": "2026-01-01T00:00:00Z"}')

    def test_can_parse_rejects_non_json(self):
        assert not self.parser.can_parse("plain text log")
        assert not self.parser.can_parse("key=value")
        assert not self.parser.can_parse("")
        assert not self.parser.can_parse("[not an object]")

    def test_parse_full_json_log(self):
        raw = '{"timestamp": "2026-09-14T10:00:00Z", "level": "ERROR", "message": "Login failed", "service": "auth", "host": "web-01", "user": "jdoe"}'
        result = self.parser.parse(raw)

        assert result.success is True
        assert result.parser_name == "json"
        assert result.parse_status == "parsed"
        assert result.timestamp == datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        assert result.level == "ERROR"
        assert result.message == "Login failed"
        assert result.service == "auth"
        assert result.host == "web-01"
        assert result.source is None  # not in JSON
        assert result.extra_data == {"user": "jdoe"}

    def test_parse_with_alt_timestamp_fields(self):
        # @timestamp (Elasticsearch style)
        raw = '{"@timestamp": "2026-09-14T10:00:00Z", "message": "test"}'
        result = self.parser.parse(raw)
        assert result.timestamp == datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)

        # time field
        raw = '{"time": "2026-09-14T10:00:00Z", "message": "test"}'
        result = self.parser.parse(raw)
        assert result.timestamp == datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)

    def test_parse_with_alt_level_fields(self):
        raw = '{"severity": "WARNING", "message": "test"}'
        result = self.parser.parse(raw)
        assert result.level == "WARNING"

        raw = '{"loglevel": "DEBUG", "message": "test"}'
        result = self.parser.parse(raw)
        assert result.level == "DEBUG"

    def test_parse_short_level_aliases(self):
        # Real-world JSON frequently uses WARN/FATAL shorthands.
        raw = '{"level": "WARN", "message": "test"}'
        assert self.parser.parse(raw).level == "WARNING"

        raw = '{"level": "FATAL", "message": "test"}'
        assert self.parser.parse(raw).level == "CRITICAL"

    def test_parse_with_alt_message_fields(self):
        raw = '{"msg": "short message", "level": "INFO"}'
        result = self.parser.parse(raw)
        assert result.message == "short message"

        raw = '{"log": "another message", "level": "INFO"}'
        result = self.parser.parse(raw)
        assert result.message == "another message"

    def test_parse_with_alt_source_fields(self):
        raw = '{"logger": "my.logger", "message": "test"}'
        result = self.parser.parse(raw)
        assert result.source == "my.logger"

    def test_parse_with_alt_host_fields(self):
        raw = '{"hostname": "server-01", "message": "test"}'
        result = self.parser.parse(raw)
        assert result.host == "server-01"

        raw = '{"machine": "vm-02", "message": "test"}'
        result = self.parser.parse(raw)
        assert result.host == "vm-02"

    def test_parse_missing_optional_fields(self):
        raw = '{"message": "just a message"}'
        result = self.parser.parse(raw)

        assert result.success is True
        assert result.timestamp is None
        assert result.level == "INFO"  # default
        assert result.message == "just a message"
        assert result.extra_data is None

    def test_parse_invalid_json(self):
        raw = '{"timestamp": "invalid", "message": "test"'
        result = self.parser.parse(raw)

        assert result.success is False
        assert result.parser_name == "json"
        assert result.parse_status == "failed"
        assert result.level == "ERROR"
        assert "Invalid JSON" in result.error
        assert result.extra_data["parse_error"] is not None

    def test_parse_non_object_json(self):
        raw = '["not", "an", "object"]'
        result = self.parser.parse(raw)

        assert result.success is False
        assert result.parse_status == "failed"
        assert "JSON root must be an object" in result.error

    def test_parse_no_message_synthesizes_from_extra(self):
        raw = '{"custom_field": "value", "another": 123}'
        result = self.parser.parse(raw)

        assert result.message == "custom_field=value | another=123"
        assert result.extra_data == {"custom_field": "value", "another": 123}

    def test_parse_level_normalization(self):
        # Case insensitive
        raw = '{"level": "error", "message": "test"}'
        result = self.parser.parse(raw)
        assert result.level == "ERROR"

        # Unknown level defaults to INFO
        raw = '{"level": "UNKNOWN", "message": "test"}'
        result = self.parser.parse(raw)
        assert result.level == "INFO"

    # --- Nested extra_data regression tests ---

    def test_parse_json_with_nested_extra_data_flattens(self):
        """JSON with extra_data field should have its contents merged, not nested."""
        raw = json.dumps({
            "timestamp": "2026-09-14T10:00:00Z",
            "level": "ERROR",
            "message": "Login failed",
            "extra_data": {
                "ip": "10.90.100.110",
                "action": "blocked",
                "synthetic": True,
                "scenario": "security_block_burst"
            }
        })
        result = self.parser.parse(raw)

        assert result.success is True
        # extra_data contents should be FLATTENED, not nested
        assert result.extra_data is not None
        assert "extra_data" not in result.extra_data, "extra_data should not be nested"
        assert result.extra_data["ip"] == "10.90.100.110"
        assert result.extra_data["action"] == "blocked"
        assert result.extra_data["synthetic"] is True
        assert result.extra_data["scenario"] == "security_block_burst"

    def test_parse_json_with_extra_data_and_other_fields_merges_all(self):
        """extra_data fields and other unknown fields should all be at top level."""
        raw = json.dumps({
            "timestamp": "2026-09-14T10:00:00Z",
            "level": "ERROR",
            "message": "Login failed",
            "ip": "10.0.0.1",  # unknown field at top level
            "extra_data": {
                "user": "admin",
                "synthetic": True
            }
        })
        result = self.parser.parse(raw)

        assert result.success is True
        assert "extra_data" not in result.extra_data
        assert result.extra_data["ip"] == "10.0.0.1"
        assert result.extra_data["user"] == "admin"
        assert result.extra_data["synthetic"] is True

    def test_parse_json_extra_data_collision_with_reserved_key_preserves_user_data(self):
        """If user extra_data contains reserved metadata keys, user data wins at parser level."""
        raw = json.dumps({
            "timestamp": "2026-09-14T10:00:00Z",
            "level": "ERROR",
            "message": "test",
            "extra_data": {
                "timestamp_source": "user_provided",  # collides with HORUS metadata
                "parser": "user_parser",
                "ip": "10.0.0.1"
            }
        })
        result = self.parser.parse(raw)

        assert result.success is True
        # User data should be preserved at the original key (parser level)
        assert result.extra_data["timestamp_source"] == "user_provided"
        assert result.extra_data["parser"] == "user_parser"
        assert result.extra_data["ip"] == "10.0.0.1"
        # HORUS metadata prefixing happens in normalizer, not parser

    def test_parse_json_nested_extra_data_with_non_dict_value(self):
        """If extra_data is not a dict, treat as regular field."""
        raw = json.dumps({
            "timestamp": "2026-09-14T10:00:00Z",
            "level": "ERROR",
            "message": "test",
            "extra_data": "not_a_dict"
        })
        result = self.parser.parse(raw)

        assert result.success is True
        # Should be treated as a regular field since it's not a dict
        assert result.extra_data["extra_data"] == "not_a_dict"

    def test_reserved_meta_keys_constant_defined(self):
        """RESERVED_META_KEYS should contain the expected keys."""
        assert "timestamp_source" in RESERVED_META_KEYS
        assert "parser" in RESERVED_META_KEYS
        assert "parse_status" in RESERVED_META_KEYS
        assert "parse_error" in RESERVED_META_KEYS