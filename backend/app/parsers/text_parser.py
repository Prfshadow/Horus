"""Plain text log parser (fallback) (M2).

Handles unstructured log lines that don't match JSON or key=value formats.
"""

from app.parsers.base import BaseParser, ParseResult, create_fallback_result


class TextParser(BaseParser):
    """Fallback parser for unstructured text logs.

    Always succeeds. Treats entire line as message.
    """

    @property
    def name(self) -> str:
        return "text"

    def can_parse(self, raw_log: str) -> bool:
        """Fallback parser matches everything (but should be last in registry)."""
        return True

    def parse(self, raw_log: str) -> ParseResult:
        """Parse unstructured text log.

        Always returns success with parse_status="fallback".
        """
        return create_fallback_result(
            parser_name=self.name,
            raw_log=raw_log,
            message=raw_log.strip() or "(empty log line)"
        )