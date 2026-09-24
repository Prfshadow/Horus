"""Tests for Syslog-style prefixed parser (M2).

Format: `2026-09-24 13:43:27 WARN  auth.service  Failed login ... ip=...`
"""

from datetime import datetime, timezone

from app.parsers.syslog_parser import SyslogParser
from app.parsers.registry import ParserRegistry
from app.parsers.json_parser import JSONParser
from app.parsers.keyvalue_parser import KeyValueParser
from app.parsers.text_parser import TextParser


class TestSyslogParser:
    def setup_method(self):
        self.parser = SyslogParser()

    def test_can_parse_prefixed_lines(self):
        assert self.parser.can_parse("2026-09-24 13:43:27 WARN  auth.service  Failed login")
        assert self.parser.can_parse("2026-09-24T13:43:27Z ERROR database Connection timeout")
        assert self.parser.can_parse("2026-9-4 3:41:02 INFO api.server Started")

    def test_can_parse_rejects_others(self):
        assert not self.parser.can_parse('{"level": "INFO"}')
        assert not self.parser.can_parse("timestamp=2026-01-01 level=INFO")
        assert not self.parser.can_parse("plain text log")
        assert not self.parser.can_parse("")
        assert not self.parser.can_parse("2026-09-24 13:43:27 BOGUS auth.service Nope")

    def test_parse_warn_line_with_pairs(self):
        raw = "2026-09-24 13:43:27 WARN  auth.service     Failed login attempt username=admin ip=10.10.5.44"
        result = self.parser.parse(raw)

        assert result.success is True
        assert result.parser_name == "syslog"
        assert result.parse_status == "parsed"
        assert result.timestamp == datetime(2026, 9, 24, 13, 43, 27, tzinfo=timezone.utc)
        assert result.level == "WARNING"
        assert result.source == "auth.service"
        assert result.service == "auth.service"
        assert result.message == "Failed login attempt username=admin ip=10.10.5.44"
        assert result.extra_data == {"username": "admin", "ip": "10.10.5.44"}

    def test_parse_error_line_without_pairs(self):
        raw = "2026-09-24 13:41:02 INFO  api.server       Server started on 0.0.0.0:8000"
        result = self.parser.parse(raw)

        assert result.success is True
        assert result.level == "INFO"
        assert result.source == "api.server"
        assert result.message == "Server started on 0.0.0.0:8000"
        assert result.extra_data is None

    def test_level_aliases(self):
        assert self.parser.parse("2026-09-24 13:43:27 WARN  svc msg").level == "WARNING"
        assert self.parser.parse("2026-09-24 13:43:27 FATAL svc msg").level == "CRITICAL"
        assert self.parser.parse("2026-09-24 13:43:27 ERROR svc msg").level == "ERROR"
        assert self.parser.parse("2026-09-24 13:43:27 DEBUG svc msg").level == "DEBUG"

    def test_iso_timestamp_with_zone(self):
        result = self.parser.parse("2026-09-24T13:43:27Z ERROR database Connection timeout")
        assert result.success is True
        assert result.timestamp == datetime(2026, 9, 24, 13, 43, 27, tzinfo=timezone.utc)
        assert result.source == "database"

    def test_pipe_delimited_line(self):
        raw = "2026-09-24T14:21:23Z | ERROR | auth | Login failed | user=admin | source=10.20.30.44"
        assert self.parser.can_parse(raw)
        result = self.parser.parse(raw)

        assert result.success is True
        assert result.timestamp == datetime(2026, 9, 24, 14, 21, 23, tzinfo=timezone.utc)
        assert result.level == "ERROR"
        assert result.source == "auth"
        assert result.message == "Login failed user=admin source=10.20.30.44"
        assert result.extra_data is not None
        assert result.extra_data["user"] == "admin"
        # IP-shaped `source=` is aliased so grouping keeps working.
        assert result.extra_data["source"] == "10.20.30.44"
        assert result.extra_data["ip"] == "10.20.30.44"

    def test_bracketed_timestamp(self):
        raw = "[2026-09-24 14:21:26] WARN authentication: account=admin status=LOCKED reason=too_many_attempts"
        assert self.parser.can_parse(raw)
        result = self.parser.parse(raw)

        assert result.success is True
        assert result.timestamp == datetime(2026, 9, 24, 14, 21, 26, tzinfo=timezone.utc)
        assert result.level == "WARNING"
        assert result.source == "authentication"
        assert result.extra_data is not None
        assert result.extra_data["account"] == "admin"

    def test_bracketed_level(self):
        raw = "2026-09-24T14:23:18Z [INFO] worker job_id=8821 status=started"
        assert self.parser.can_parse(raw)
        result = self.parser.parse(raw)

        assert result.success is True
        assert result.level == "INFO"
        assert result.source == "worker"
        assert result.extra_data is not None
        assert result.extra_data["job_id"] == "8821"

    def test_non_ip_source_not_aliased(self):
        raw = "2026-09-24 13:41:02 INFO api x source=auth-service"
        result = self.parser.parse(raw)

        assert result.success is True
        assert result.extra_data is not None
        assert result.extra_data["source"] == "auth-service"
        assert "ip" not in result.extra_data

    def test_registry_prefers_syslog_over_keyvalue(self):
        """Prefixed lines containing '=' must reach SyslogParser, not KeyValueParser."""
        registry = ParserRegistry()
        registry.register(JSONParser())
        registry.register(SyslogParser())
        registry.register(KeyValueParser())
        registry.register(TextParser(), is_fallback=True)

        r = registry.parse("2026-09-24 13:43:27 WARN  auth.service  Failed login username=admin ip=10.10.5.44")
        assert r.parser_name == "syslog"
        assert r.level == "WARNING"
        assert r.timestamp == datetime(2026, 9, 24, 13, 43, 27, tzinfo=timezone.utc)

        # Other formats still route correctly.
        assert registry.parse('{"level": "INFO", "message": "hi"}').parser_name == "json"
        assert registry.parse("level=INFO message=hi").parser_name == "keyvalue"
        assert registry.parse("just some words").parser_name == "text"
