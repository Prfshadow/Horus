"""Tests for Key=Value parser (M2)."""

from datetime import datetime, timezone

from app.parsers.keyvalue_parser import KeyValueParser
from app.parsers.base import ParseResult


class TestKeyValueParser:
    """Test KeyValueParser.can_parse and KeyValueParser.parse."""

    def setup_method(self):
        self.parser = KeyValueParser()

    def test_can_parse_valid_kv(self):
        assert self.parser.can_parse("key=value")
        assert self.parser.can_parse("timestamp=2026-01-01 level=INFO message=hello")
        assert self.parser.can_parse('user="john doe" action=login')

    def test_can_parse_rejects_json(self):
        assert not self.parser.can_parse('{"message": "hello"}')

    def test_can_parse_rejects_plain_text(self):
        assert not self.parser.can_parse("plain text log")
        assert not self.parser.can_parse("")

    def test_parse_basic_kv_pairs(self):
        raw = "timestamp=2026-09-14T10:00:00Z level=ERROR message=\"Login failed\" user=jdoe"
        result = self.parser.parse(raw)

        assert result.success is True
        assert result.parser_name == "keyvalue"
        assert result.parse_status == "parsed"
        assert result.timestamp == datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        assert result.level == "ERROR"
        assert result.message == "Login failed"
        assert result.extra_data == {"user": "jdoe"}

    def test_parse_double_quoted_values(self):
        raw = 'message="Login failed for user jdoe" level=INFO'
        result = self.parser.parse(raw)

        assert result.message == "Login failed for user jdoe"
        assert result.level == "INFO"

    def test_parse_single_quoted_values(self):
        raw = "message='Login failed' level=INFO"
        result = self.parser.parse(raw)

        assert result.message == "Login failed"

    def test_parse_unquoted_values(self):
        raw = "message=SimpleMessage level=INFO"
        result = self.parser.parse(raw)

        assert result.message == "SimpleMessage"

    def test_parse_escaped_quotes_in_double_quoted(self):
        raw = 'message="He said \\"hello\\"" level=INFO'
        result = self.parser.parse(raw)

        assert result.message == 'He said "hello"'

    def test_parse_with_alt_fields(self):
        raw = "@timestamp=2026-09-14T10:00:00Z severity=WARNING msg=test logger=myapp"
        result = self.parser.parse(raw)

        assert result.timestamp == datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
        assert result.level == "WARNING"
        assert result.message == "test"
        assert result.source == "myapp"

    def test_parse_missing_optional_fields(self):
        raw = "message=hello"
        result = self.parser.parse(raw)

        assert result.timestamp is None
        assert result.level == "INFO"
        assert result.message == "hello"
        assert result.extra_data is None

    def test_parse_no_message_synthesizes_from_extra(self):
        raw = "user=jdoe action=login status=success"
        result = self.parser.parse(raw)

        assert result.message == "user=jdoe | action=login | status=success"
        assert result.extra_data == {"user": "jdoe", "action": "login", "status": "success"}

    def test_parse_invalid_no_pairs(self):
        raw = "plain text without equals"
        result = self.parser.parse(raw)

        assert result.success is False
        assert result.parse_status == "failed"
        assert "No key=value pairs found" in result.error

    def test_parse_level_normalization(self):
        raw = "level=error message=test"
        result = self.parser.parse(raw)
        assert result.level == "ERROR"

        raw = "level=WARN message=test"
        assert self.parser.parse(raw).level == "WARNING"

        raw = "level=UNKNOWN message=test"
        result = self.parser.parse(raw)
        assert result.level == "INFO"