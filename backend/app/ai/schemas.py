"""M6 AI schemas — structured InvestigationAnalysis."""

from datetime import datetime
from typing import Optional, Literal

from pydantic import BaseModel, Field, field_validator


class Observation(BaseModel):
    statement: str = Field(min_length=1, max_length=500)
    type: Literal["fact", "inference", "uncertainty"]
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: Optional[Literal["low", "medium", "high"]] = None

    @field_validator("evidence_ids")
    @classmethod
    def _check_ids_format(cls, v):
        for item in v:
            if not isinstance(item, str) or ":" not in item:
                raise ValueError(f"Invalid evidence id format: {item}")
        return v


class AlternativeExplanation(BaseModel):
    explanation: str = Field(min_length=1, max_length=500)
    evidence_ids: list[str] = Field(default_factory=list)


class Provenance(BaseModel):
    provider: str
    model: str
    prompt_version: str
    schema_version: str
    incident_id: int
    evidence_ids_used: list[str]
    truncated: bool
    created_at: datetime


class InvestigationAnalysis(BaseModel):
    summary: str = Field(min_length=1, max_length=1000)
    observations: list[Observation] = Field(min_length=1, max_length=10)
    supporting_evidence: list[str] = Field(default_factory=list)
    alternative_explanations: list[AlternativeExplanation] = Field(default_factory=list, max_length=3)
    recommended_steps: list[str] = Field(default_factory=list, max_length=5)
    limitations: list[str] = Field(default_factory=list, max_length=5)
    provenance: Optional[Provenance] = None

    @field_validator("supporting_evidence")
    @classmethod
    def _check_supporting(cls, v):
        for item in v:
            if ":" not in item:
                raise ValueError(f"Invalid supporting evidence id: {item}")
        return v
