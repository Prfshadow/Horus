"""Validators for M6 structured output."""

import json
import re
from typing import Any

from pydantic import ValidationError as PydanticValidationError

from app.ai.schemas import InvestigationAnalysis


def extract_json(raw: str) -> str:
    """Extract JSON from raw text (strip fences, find first {...} )."""
    text = raw.strip()
    # Remove ```json fences
    if "```" in text:
        # Find first { and last }
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if m:
            return m.group(1)
        # Fallback: extract between ``` 
        parts = text.split("```")
        for p in parts:
            p = p.strip()
            if p.startswith("{") and p.endswith("}"):
                return p
    # Find outermost JSON object
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start:end+1]
    return text


def validate_investigation_analysis(raw_text: str, allowed_ids: set[str]) -> InvestigationAnalysis:
    """Full validation pipeline. Raises ValidationError with 502 semantics."""
    json_str = extract_json(raw_text)
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Malformed JSON: {e}")

    try:
        analysis = InvestigationAnalysis.model_validate(data)
    except PydanticValidationError as e:
        raise ValueError(f"Schema validation failed: {e}")

    # Evidence citation validation
    for obs in analysis.observations:
        for eid in obs.evidence_ids:
            if eid not in allowed_ids:
                raise ValueError(f"Unknown evidence ID: {eid}")
        # Fact/inference/uncertainty rules
        if obs.type == "fact":
            if not obs.evidence_ids:
                raise ValueError(f"fact observation requires evidence_ids: {obs.statement}")
            if obs.confidence is not None:
                raise ValueError(f"fact must have confidence null: {obs.statement}")
        elif obs.type == "inference":
            if not obs.evidence_ids:
                raise ValueError(f"inference requires evidence_ids: {obs.statement}")
            if obs.confidence not in ("low", "medium", "high"):
                raise ValueError(f"inference requires confidence low/medium/high: {obs.statement}")
        elif obs.type == "uncertainty":
            if obs.confidence is not None:
                raise ValueError(f"uncertainty must have confidence null: {obs.statement}")

    for alt in analysis.alternative_explanations:
        for eid in alt.evidence_ids:
            if eid not in allowed_ids:
                raise ValueError(f"Unknown evidence ID in alternative: {eid}")

    for eid in analysis.supporting_evidence:
        if eid not in allowed_ids:
            raise ValueError(f"Unknown supporting evidence ID: {eid}")

    return analysis
