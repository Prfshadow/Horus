"""FastAPI application factory (M1+M2+M3).

`create_app()` builds a fresh app instance so tests can inject an
isolated database without touching the dev `horus.db` file.
"""

from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

from fastapi import FastAPI
from sqlalchemy import select

from app.api.v1 import admin, alerts, correlation, detection, events, health, incidents, ingestion, investigate, investigation, rules, stats, threat_assessment
from app.core.config import settings
from app.core.logging_config import configure_logging, get_logger
from app.db.session import SessionLocal, init_db
from app.parsers.json_parser import JSONParser
from app.parsers.keyvalue_parser import KeyValueParser
from app.parsers.registry import parser_registry
from app.parsers.syslog_parser import SyslogParser
from app.parsers.text_parser import TextParser

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Run startup/shutdown logic (tables + logging + parser + detection registration)."""
    init_db()

    # Register parsers (order matters: specific first, fallback last)
    # Clear first for reload safety
    parser_registry.reset()
    parser_registry.register(JSONParser())
    # Syslog BEFORE keyvalue: prefixed lines often contain "=" and the
    # keyvalue reader would claim them while dropping timestamp/level/source.
    parser_registry.register(SyslogParser())
    parser_registry.register(KeyValueParser())
    parser_registry.register(TextParser(), is_fallback=True)

    # Detection: ensure default rules exist and register rule classes/instances
    try:
        from app.models.detection_rule import DetectionRule
        from app.detection.registry import rule_registry
        from app.detection.rules.brute_force import BruteForceLoginRule
        from app.detection.rules.error_spike import ErrorSpikeRule
        from app.detection.rules.port_scan import PortScanRule
        from app.detection.rules.web_scan import WebScanRule
        from app.detection.rules.authentication_anomaly import AuthenticationAnomalyRule
        from app.detection.rules.sql_injection import SQLInjectionRule
        from app.detection.rules.xss_attempt import XSSAttemptRule
        from app.detection.rules.malware_detection import MalwareDetectionRule
        from app.detection.rules.privilege_escalation import PrivilegeEscalationRule
        from app.detection.rules.suspicious_process import SuspiciousProcessRule
        from app.detection.rules.dns_anomaly import DNSAnomalyRule
        from app.detection.rules.api_abuse import APIAbuseRule
        from app.detection.rules.data_transfer_anomaly import DataTransferAnomalyRule
        from app.detection.rules.account_takeover import AccountTakeoverRule
        from app.detection.rules.security_block_burst import SecurityBlockBurstRule
        from app.services.detection import ensure_default_rules

        # Register rule classes (rule_type -> class)
        rule_registry.register_class("threshold", BruteForceLoginRule)
        rule_registry.register_class("frequency", ErrorSpikeRule)
        rule_registry.register_class("port_scan", PortScanRule)
        rule_registry.register_class("web_scan", WebScanRule)
        rule_registry.register_class("authentication_anomaly", AuthenticationAnomalyRule)
        rule_registry.register_class("sql_injection", SQLInjectionRule)
        rule_registry.register_class("xss_attempt", XSSAttemptRule)
        rule_registry.register_class("malware_detection", MalwareDetectionRule)
        rule_registry.register_class("privilege_escalation", PrivilegeEscalationRule)
        rule_registry.register_class("suspicious_process", SuspiciousProcessRule)
        rule_registry.register_class("dns_anomaly", DNSAnomalyRule)
        rule_registry.register_class("api_abuse", APIAbuseRule)
        rule_registry.register_class("data_transfer_anomaly", DataTransferAnomalyRule)
        rule_registry.register_class("account_takeover", AccountTakeoverRule)
        rule_registry.register_class("security_block_burst", SecurityBlockBurstRule)

        # Ensure default rules in DB
        with SessionLocal() as db:
            ensure_default_rules(db)
            # Register instances for enabled rules
            rule_registry.clear_instances()
            enabled = db.execute(select(DetectionRule).where(DetectionRule.enabled.is_(True))).scalars().all()
            for rm in enabled:
                cls = rule_registry.get_class(rm.rule_type)
                if cls:
                    inst = cls(config=rm.config)
                    # Override name to match DB name (class default may differ)
                    inst.name = rm.name
                    rule_registry.register_instance(rm.name, inst)

        logger.debug("Registered detection rules: %s", rule_registry.get_all_names())
    except Exception as exc:
        logger.warning("Detection registration failed: %s", exc)

    logger.info("%s starting (env=%s)", settings.app_name, settings.app_env)
    # Provider + model only — never log the API key.
    logger.info("AI provider=%s model=%s", settings.ai_provider, settings.ai_model)
    logger.debug("Registered parsers: %s", [p.name for p in parser_registry.parsers])
    logger.debug("Fallback parser: %s", parser_registry.fallback_parser.name if parser_registry.fallback_parser else None)

    yield


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    configure_logging(settings.log_level)

    app = FastAPI(title=settings.app_name, lifespan=lifespan)

    app.include_router(admin.router, prefix="/api/v1")
    app.include_router(health.router, prefix="/api/v1")
    app.include_router(events.router, prefix="/api/v1")
    app.include_router(ingestion.router, prefix="/api/v1")
    app.include_router(alerts.router, prefix="/api/v1")
    app.include_router(rules.router, prefix="/api/v1")
    app.include_router(detection.router, prefix="/api/v1")
    app.include_router(incidents.router, prefix="/api/v1")
    app.include_router(correlation.router, prefix="/api/v1")
    app.include_router(investigation.router, prefix="/api/v1")
    app.include_router(investigate.router, prefix="/api/v1")
    app.include_router(stats.router, prefix="/api/v1")
    app.include_router(threat_assessment.router, prefix="/api/v1")

    @app.get("/", tags=["root"])
    def root() -> dict:
        return {"app": settings.app_name, "docs": "/docs", "health": "/api/v1/health"}

    return app


app = create_app()
