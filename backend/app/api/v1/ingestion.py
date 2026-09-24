"""Batch log ingestion endpoint (M2).

POST /api/v1/ingest - Accept raw logs, parse, normalize, store.
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.db.session import get_db
from app.normalizers.event_normalizer import EventNormalizer
from app.schemas.ingestion import IngestResponse, RawLogBatch
from app.services.ingestion import IngestionService

router = APIRouter(prefix="/ingest", tags=["ingestion"])
logger = get_logger(__name__)

# Service instance (stateless, can be reused)
ingestion_service = IngestionService(normalizer=EventNormalizer())


@router.post("", response_model=IngestResponse, status_code=status.HTTP_200_OK)
def ingest_logs(payload: RawLogBatch, db: Session = Depends(get_db)) -> IngestResponse:
    """Ingest a batch of raw log lines.

    Each log is parsed independently. Parser failures for one log
    do not affect other logs in the batch.

    Request:
        {
            "logs": ["log line 1", "log line 2", ...],
            "source": "optional-default-source"
        }

    Response:
        {
            "accepted": 99,
            "failed": 1,
            "results": [
                {"index": 0, "event_id": 42, "status": "stored"},
                {"index": 1, "event_id": 43, "status": "parse_error", "error": "..."}
            ]
        }
    """
    logger.info("Ingesting batch of %d logs (source=%s)", len(payload.logs), payload.source)

    try:
        results = ingestion_service.ingest_batch(
            raw_logs=payload.logs,
            db=db,
            default_source=payload.source,
        )

        # Set correct index on each result
        for i, result in enumerate(results):
            result.index = i

        # Commit all successfully parsed events
        db.commit()

        accepted = sum(1 for r in results if r.status == "stored")
        failed = sum(1 for r in results if r.status == "parse_error")

        logger.info("Batch ingested: %d stored, %d parse errors", accepted, failed)

        return IngestResponse(
            accepted=accepted,
            failed=failed,
            results=results,
        )

    except Exception:
        db.rollback()
        logger.exception("Batch ingestion failed with system error")
        raise