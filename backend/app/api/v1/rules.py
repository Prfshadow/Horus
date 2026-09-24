"""Rules API (M3)."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.logging_config import get_logger
from app.db.session import get_db
from app.models.detection_rule import DetectionRule
from app.schemas.detection import DetectionRuleRead, DetectionRuleUpdate

router = APIRouter(prefix="/rules", tags=["rules"])
logger = get_logger(__name__)


@router.get("", response_model=list[DetectionRuleRead])
def list_rules(
    enabled: Optional[bool] = None,
    db: Session = Depends(get_db),
) -> list[DetectionRuleRead]:
    stmt = select(DetectionRule).order_by(DetectionRule.name)
    if enabled is not None:
        stmt = stmt.where(DetectionRule.enabled == enabled)
    rules = list(db.execute(stmt).scalars().all())
    return [DetectionRuleRead.model_validate(r) for r in rules]


@router.get("/{name}", response_model=DetectionRuleRead)
def get_rule(name: str, db: Session = Depends(get_db)) -> DetectionRuleRead:
    rule = db.execute(select(DetectionRule).where(DetectionRule.name == name)).scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return DetectionRuleRead.model_validate(rule)


@router.patch("/{name}", response_model=DetectionRuleRead)
def update_rule(name: str, payload: DetectionRuleUpdate, db: Session = Depends(get_db)) -> DetectionRuleRead:
    rule = db.execute(select(DetectionRule).where(DetectionRule.name == name)).scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    if payload.enabled is not None:
        rule.enabled = payload.enabled
        db.commit()
        db.refresh(rule)
        logger.info("Rule %s enabled=%s", name, payload.enabled)
    return DetectionRuleRead.model_validate(rule)
