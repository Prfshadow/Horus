"""AIInvestigator — orchestrates M5 -> selector -> prompt -> provider -> validation."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.ai.evidence_selector import EvidenceSelector
from app.ai.prompt import PromptBuilder
from app.ai.provider import LLMProvider, ProviderRequest, ProviderError, get_provider
from app.ai.schemas import InvestigationAnalysis, Provenance
from app.ai.validators import validate_investigation_analysis
from app.investigation.service import InvestigationService
from app.core.config import settings


class AIInvestigator:
    def __init__(
        self,
        investigation_service: Optional[InvestigationService] = None,
        selector: Optional[EvidenceSelector] = None,
        prompt_builder: Optional[PromptBuilder] = None,
        provider: Optional[LLMProvider] = None,
    ):
        self.investigation_service = investigation_service or InvestigationService()
        self.selector = selector or EvidenceSelector()
        self.prompt_builder = prompt_builder or PromptBuilder()
        self._provider = provider  # lazy via get_provider if None

    def _get_provider(self) -> LLMProvider:
        if self._provider:
            return self._provider
        return get_provider()

    async def investigate(self, db: Session, incident_id: int) -> dict:
        # 1. Get M5 context (dynamic)
        try:
            ctx = self.investigation_service.get_investigation(db, incident_id)
        except ValueError as e:
            raise ValueError(str(e))
        except Exception as e:
            raise RuntimeError(f"Database failure: {e}")

        # Empty incident check: no alerts and no events
        if not ctx["alerts"] and not ctx["events"]:
            # Deterministic insufficient evidence response without calling LLM
            analysis = InvestigationAnalysis(
                summary="Insufficient evidence available for AI investigation: incident contains no alerts or events.",
                observations=[
                    {
                        "statement": "No alerts or events are linked to this incident.",
                        "type": "fact",
                        "evidence_ids": [f"incident:{incident_id}"],
                        "confidence": None,
                    },
                    {
                        "statement": "Investigation cannot proceed without evidence.",
                        "type": "uncertainty",
                        "evidence_ids": [],
                        "confidence": None,
                    },
                ],
                supporting_evidence=[],
                alternative_explanations=[],
                recommended_steps=["Ingest relevant logs", "Run detection and correlation to generate alerts"],
                limitations=["No evidence available for analysis"],
            )
            provenance = Provenance(
                provider="deterministic",
                model="no-llm",
                prompt_version=settings.ai_prompt_version,
                schema_version=settings.ai_schema_version,
                incident_id=incident_id,
                evidence_ids_used=[f"incident:{incident_id}"],
                truncated=False,
                created_at=datetime.now(timezone.utc),
            )
            analysis.provenance = provenance
            return {
                "incident_id": incident_id,
                "analysis": analysis,
                "evidence_meta": {
                    "alerts_used": 0,
                    "events_used": 0,
                    "truncated": False,
                    "total_alerts": 0,
                    "total_events": 0,
                },
                "provenance": provenance,
            }

        # 2. Evidence selection (deterministic, bounded, no DB)
        relevant = self.selector.select(ctx)
        allowed_ids = set(relevant["allowed_ids"])

        # 3. Prompt building
        prompt = self.prompt_builder.build(relevant)

        # 4. Provider call
        provider = self._get_provider()
        # Build JSON schema for provider (optional, for Gemini structured output)
        json_schema = InvestigationAnalysis.model_json_schema()
        req = ProviderRequest(
            prompt=prompt,
            model=settings.ai_model,
            json_schema=json_schema,
            timeout_s=settings.ai_timeout,
            max_output_tokens=2000,
            temperature=0.2,
        )
        try:
            resp = await provider.generate(req)
        except ProviderError:
            raise
        except Exception as e:
            raise ProviderError("unavailable", str(e))

        # 5. Validation pipeline
        try:
            analysis = validate_investigation_analysis(resp.raw_text, allowed_ids)
        except ValueError as e:
            # Malformed or invalid citation -> 502
            raise ProviderError("malformed_response", str(e))

        # 6. Provenance (server-generated, not LLM)
        provenance = Provenance(
            provider=settings.ai_provider,
            model=settings.ai_model,
            prompt_version=settings.ai_prompt_version,
            schema_version=settings.ai_schema_version,
            incident_id=incident_id,
            evidence_ids_used=sorted(allowed_ids),
            truncated=relevant["truncation"]["evidence_truncated"],
            created_at=datetime.now(timezone.utc),
        )
        analysis.provenance = provenance

        return {
            "incident_id": incident_id,
            "analysis": analysis,
            "evidence_meta": {
                "alerts_used": len(relevant["alerts"]),
                "events_used": len(relevant["events"]),
                "truncated": relevant["truncation"]["evidence_truncated"],
                "total_alerts": relevant["truncation"]["total_alerts"],
                "total_events": relevant["truncation"]["total_events"],
            },
            "provenance": provenance,
        }
