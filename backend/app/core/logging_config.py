"""Centralized stdlib logging configuration (M1).

Human-readable console output is sufficient for local development.
JSON structured logging will be introduced when log aggregation
infrastructure exists (post-M1 decision, see README).
"""

import logging
import sys


def configure_logging(level: str = "INFO") -> None:
    """Configure root logger once at application startup."""
    log_level = getattr(logging, level.upper(), logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    root = logging.getLogger()
    root.setLevel(log_level)

    # Avoid duplicate handlers on reload (uvicorn --reload, tests).
    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        root.addHandler(handler)
    else:
        # Ensure level stays in sync even if handler already exists.
        for h in root.handlers:
            h.setLevel(log_level)


def get_logger(name: str) -> logging.Logger:
    """Return a module-level logger."""
    return logging.getLogger(name)
