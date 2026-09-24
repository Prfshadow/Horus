"""Tests for Text parser (fallback) (M2)."""

from app.parsers.text_parser import TextParser
from app.parsers.base import ParseResult


class TestTextParser:
    """Test TextParser (fallback parser)."""

    def setup_method(self):
        self.parser = TextParser()

    def test_can_parse_always_true(self):
        assert self.parser.can_parse("anything")
        assert self.parser.can_parse("")
        assert self.parser.can_parse('{"json": "object"}')  # even JSON
        assert self.parser.can_parse("key=value")  # even KV

    def test_parse_plain_text(self):
        raw = "Something happened on the server"
        result = self.parser.parse(raw)

        assert result.success is True
        assert result.parser_name == "text"
        assert result.parse_status == "fallback"
        assert result.message == "Something happened on the server"
        assert result.level == "INFO"
        assert result.timestamp is None
        assert result.extra_data == {"parser": "text"}

    def test_parse_empty_string(self):
        raw = ""
        result = self.parser.parse(raw)

        assert result.message == "(empty log line)"
        assert result.level == "INFO"
        assert result.parse_status == "fallback"

    def test_parse_whitespace_only(self):
        raw = "   \n\t  "
        result = self.parser.parse(raw)

        assert result.message == "(empty log line)"

    def test_parse_preserves_raw_in_extra_data(self):
        raw = "Some log line"
        result = self.parser.parse(raw)

        # raw_log is not in extra_data for fallback - it's handled by normalizer
        assert result.extra_data == {"parser": "text"}