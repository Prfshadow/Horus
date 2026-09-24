"""Parser registry for format detection and dispatch (M2)."""

from typing import Optional

from app.parsers.base import BaseParser, ParseResult, create_failed_result


class ParserRegistry:
    """Registry of log parsers with automatic format detection.

    Parsers are tried in registration order. First match wins.
    """

    def __init__(self):
        self._parsers: list[BaseParser] = []
        self._fallback_parser: Optional[BaseParser] = None

    def register(self, parser: BaseParser, is_fallback: bool = False) -> None:
        """Register a parser.

        Args:
            parser: Parser instance implementing BaseParser.
            is_fallback: If True, this parser is used when no other matches.
                        Only one fallback parser allowed.
        """
        if is_fallback:
            if self._fallback_parser is not None:
                raise ValueError("Fallback parser already registered")
            self._fallback_parser = parser
        else:
            self._parsers.append(parser)

    def detect_format(self, raw_log: str) -> BaseParser:
        """Detect appropriate parser for a log line.

        Returns the first parser where can_parse() returns True.
        Falls back to fallback parser if none match.
        """
        for parser in self._parsers:
            if parser.can_parse(raw_log):
                return parser
        if self._fallback_parser is not None:
            return self._fallback_parser
        raise RuntimeError("No fallback parser registered")

    def parse(self, raw_log: str) -> ParseResult:
        """Parse a log line using auto-detected parser.

        Never raises. Returns failed ParseResult on detection/parse errors.
        """
        try:
            parser = self.detect_format(raw_log)
            return parser.parse(raw_log)
        except Exception as e:
            return create_failed_result("registry", f"Detection failed: {e}", raw_log)

    @property
    def parsers(self) -> list[BaseParser]:
        """Return all registered parsers (excluding fallback)."""
        return list(self._parsers)

    @property
    def fallback_parser(self) -> Optional[BaseParser]:
        return self._fallback_parser

    def reset(self) -> None:
        """Clear all registered parsers. Used for testing."""
        self._parsers.clear()
        self._fallback_parser = None


# Global registry instance (populated during app startup)
parser_registry = ParserRegistry()