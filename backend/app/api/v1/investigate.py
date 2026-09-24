"""M6 AI Investigation API — POST /incidents/{id}/investigate"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.db.session import get_db
from app.ai.investigator import AIInvestigator
from app.ai.provider import ProviderError

router = APIRouter(prefix="/incidents", tags=["ai-investigation"])
logger = get_logger(__name__)


@router.post("/{incident_id}/investigate")
async def investigate_incident(incident_id: int, db: Session = Depends(get_db)):
    investigator = AIInvestigator()
    try:
        result = await investigator.investigate(db, incident_id)
    except ValueError as e:
        if "not found" in str(e).lower():
            raise HTTPException(status_code=404, detail="Incident not found")
        raise HTTPException(status_code=422, detail=str(e))
    except ProviderError as e:
        if e.code in ("timeout", "unavailable", "authentication", "rate_limit"):
            # ProviderError messages are sanitized (no keys/secrets), so
            # logging them gives operators the exact failure in the terminal.
            logger.warning("AI provider error for incident %s: %s: %s", incident_id, e.code, e)
            raise HTTPException(status_code=503, detail=f"AI provider error: {e.code}: {e}")
        elif e.code in ("malformed_response",):
            # Log the validation reason server-side (schema error / bad
            # citation); the UI only shows a generic message.
            logger.warning("AI validation failed for incident %s: %s", incident_id, e)
            raise HTTPException(status_code=502, detail=f"Invalid AI response: {e}")
        else:
            raise HTTPException(status_code=503, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.exception("Investigation failed for incident %s", incident_id)
        raise HTTPException(status_code=500, detail="Internal error")

    analysis = result["analysis"]
    return {
        "incident_id": result["incident_id"],
        "analysis": analysis.model_dump(mode="json"),
        "evidence_meta": result["evidence_meta"],
        "provenance": result["provenance"].model_dump(mode="json"),
    }
