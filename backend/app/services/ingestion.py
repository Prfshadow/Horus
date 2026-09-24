"""Ingestion service: orchestrates parsing, normalization, and persistence (M2)."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models.event import Event
from app.normalizers.event_normalizer import EventNormalizer
from app.parsers.base import ParseResult
from app.parsers.registry import parser_registry
from app.schemas.ingestion import IngestResult


@dataclass
class IngestionService:
    """Service layer for log ingestion.

    Coordinates:
    - ParserRegistry for format detection and parsing
    - EventNormalizer for ParseResult -> EventCreate conversion
    - Database persistence via SQLAlchemy session
    """

    normalizer: EventNormalizer
    registry = parser_registry

    def ingest_batch(
        self,
        raw_logs: list[str],
        db: Session,
        default_source: Optional[str] = None,
    ) -> list[IngestResult]:
        """Ingest a batch of raw log lines.

        Each log is processed independently. Parser failures for one log
        do not affect other logs in the batch.

        Args:
            raw_logs: List of raw log strings (preserved exactly)
            db: Database session
            default_source: Default source for logs without parsed source

        Returns:
            List of IngestResult (one per input log, in same order)
        """
        results = []
        ingestion_time = datetime.now(timezone.utc)

        for index, raw_log in enumerate(raw_logs):
            try:
                result = self._ingest_single(raw_log, db, ingestion_time, default_source)
                results.append(result)
            except Exception as e:
                # Database/system errors - not silently swallowed
                # But we still record a result for this log
                results.append(IngestResult(
                    index=index,
                    event_id=None,
                    status="system_error",
                    error=f"System error during ingestion: {e}",
                ))
                # Re-raise to let caller decide (transaction rollback, etc.)
                raise

        return results

    def _ingest_single(
        self,
        raw_log: str,
        db: Session,
        ingestion_time: datetime,
        default_source: Optional[str],
    ) -> IngestResult:
        """Ingest a single raw log line.

        Returns IngestResult with event_id if stored, or error info.
        """
        # Parse
        parse_result = self.registry.parse(raw_log)

        # Normalize to EventCreate
        event_create = self.normalizer.normalize(
            parse_result=parse_result,
            raw_log=raw_log,
            ingestion_time=ingestion_time,
            default_source=default_source,
        )

        # Persist
        event = Event(
            timestamp=event_create.timestamp,
            source=event_create.source,
            level=event_create.level,
            service=event_create.service,
            host=event_create.host,
            message=event_create.message,
            raw_log=event_create.raw_log,  # Preserved exactly
            extra_data=event_create.extra_data,
        )
        db.add(event)
        db.flush()  # Get ID without committing transaction

        return IngestResult(
            index=0,  # Will be set by caller
            event_id=event.id,
            status="stored" if parse_result.parse_status != "failed" else "parse_error",
            error=parse_result.error if parse_result.parse_status == "failed" else None,
        )