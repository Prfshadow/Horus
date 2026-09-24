"""Ingestion API schemas (M2)."""

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class RawLogBatch(BaseModel):
    """Request body for batch log ingestion."""

    logs: list[str] = Field(
        min_length=1,
        max_length=1000,
        description="Raw log lines to ingest. Each string is preserved exactly."
    )
    source: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Default source for logs that don't have one parsed."
    )


class IngestResult(BaseModel):
    """Result for a single log in the batch."""

    index: int = Field(description="Position in the input batch (0-based)")
    event_id: Optional[int] = Field(
        default=None,
        description="Database ID of stored event, if successful"
    )
    status: Literal["stored", "parse_error", "system_error"] = Field(
        description="Outcome: stored=success, parse_error=parser failed, system_error=DB error"
    )
    error: Optional[str] = Field(
        default=None,
        description="Error details if status != 'stored'"
    )


class IngestResponse(BaseModel):
    """Response for batch ingestion."""

    model_config = ConfigDict(from_attributes=True)

    accepted: int = Field(description="Number of logs successfully stored")
    failed: int = Field(description="Number of logs with parse errors")
    results: list[IngestResult] = Field(description="Per-log results in input order")