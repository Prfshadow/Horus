"""Tests for ParserRegistry (M2)."""

from app.parsers.registry import ParserRegistry
from app.parsers.json_parser import JSONParser
from app.parsers.keyvalue_parser import KeyValueParser
from app.parsers.text_parser import TextParser
from app.parsers.base import ParseResult


class TestParserRegistry:
    """Test ParserRegistry detection and parsing."""

    def setup_method(self):
        self.registry = ParserRegistry()
        self.registry.register(JSONParser())
        self.registry.register(KeyValueParser())
        self.registry.register(TextParser(), is_fallback=True)

    def test_detect_json_format(self):
        parser = self.registry.detect_format('{"message": "hello"}')
        assert parser.name == "json"

    def test_detect_keyvalue_format(self):
        parser = self.registry.detect_format("key=value message=hello")
        assert parser.name == "keyvalue"

    def test_detect_text_fallback(self):
        parser = self.registry.detect_format("plain text log")
        assert parser.name == "text"

    def test_parse_json_via_registry(self):
        raw = '{"timestamp": "2026-09-14T10:00:00Z", "level": "ERROR", "message": "test"}'
        result = self.registry.parse(raw)

        assert result.success is True
        assert result.parser_name == "json"
        assert result.parse_status == "parsed"
        assert result.level == "ERROR"

    def test_parse_keyvalue_via_registry(self):
        raw = "timestamp=2026-09-14T10:00:00Z level=INFO message=test"
        result = self.registry.parse(raw)

        assert result.success is True
        assert result.parser_name == "keyvalue"
        assert result.parse_status == "parsed"

    def test_parse_text_fallback_via_registry(self):
        raw = "plain text log line"
        result = self.registry.parse(raw)

        assert result.success is True
        assert result.parser_name == "text"
        assert result.parse_status == "fallback"
        assert result.level == "INFO"

    def test_json_preferred_over_text(self):
        # JSON should be detected before text fallback
        raw = '{"message": "hello"}'
        parser = self.registry.detect_format(raw)
        assert parser.name == "json"

    def test_keyvalue_preferred_over_text(self):
        raw = "key=value"
        parser = self.registry.detect_format(raw)
        assert parser.name == "keyvalue"

    def test_registration_order_matters(self):
        # First registered parser that matches wins
        registry = ParserRegistry()
        registry.register(TextParser())  # Register text first (not as fallback)
        registry.register(JSONParser())
        registry.register(KeyValueParser())
        registry.register(TextParser(), is_fallback=True)

        # Text parser (non-fallback) will match everything first
        parser = registry.detect_format('{"message": "hello"}')
        assert parser.name == "text"

    def test_duplicate_fallback_raises(self):
        registry = ParserRegistry()
        registry.register(TextParser(), is_fallback=True)

        try:
            registry.register(TextParser(), is_fallback=True)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Fallback parser already registered" in str(e)

    def test_no_fallback_raises(self):
        registry = ParserRegistry()
        registry.register(JSONParser())

        try:
            registry.detect_format("plain text")
            assert False, "Should have raised RuntimeError"
        except RuntimeError as e:
            assert "No fallback parser registered" in str(e)

    def test_reset_clears_parsers(self):
        self.registry.reset()
        assert len(self.registry.parsers) == 0
        assert self.registry.fallback_parser is None

    def test_parse_handles_parser_exceptions(self):
        # Registry.parse never raises, returns failed ParseResult
        class BrokenParser:
            name = "broken"
            def can_parse(self, raw_log): return True
            def parse(self, raw_log): raise ValueError("boom")

        registry = ParserRegistry()
        registry.register(BrokenParser())
        registry.register(TextParser(), is_fallback=True)

        result = registry.parse("test")
        assert result.success is False
        assert result.parse_status == "failed"
        assert "Detection failed" in result.error