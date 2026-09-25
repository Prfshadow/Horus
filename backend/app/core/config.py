"""Application settings loaded from environment variables.

Single source of truth for configuration (M1).
Uses pydantic-settings so every setting can be overridden via env vars
or a local `.env` file. No secrets are hardcoded.
"""

from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Anchor the .env file to the backend directory (the one holding
# requirements.txt), NOT the process working directory. Previously a
# relative ".env" meant launching uvicorn from the repo root silently
# read the root .env instead of backend/.env, dropping AI_* settings.
_BACKEND_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    """Runtime configuration for HORUS backend."""

    model_config = SettingsConfigDict(
        env_file=str(_BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Horus"
    app_env: str = "dev"
    log_level: str = "INFO"

    # SQLite for M1 local dev. PostgreSQL-compatible: switching this URL
    # to e.g. postgresql+psycopg2://... requires no code changes.
    # On Render, use /data/horus.db (writable, but ephemeral on free tier).
    database_url: str = "sqlite:///./horus.db"

    # CORS allowed origins (comma-separated). Set via env var in production.
    cors_allowed_origins: str = "http://localhost:5173,http://localhost:8080"

    # M6 AI Investigation (server-side only, never from API request)
    ai_provider: str = "disabled"  # disabled | gemini | groq | ollama | mock
    ai_model: str = "gemini-2.5-flash"
    ai_api_key: str = ""
    ai_groq_api_key: str = ""
    ai_timeout: int = 30
    ai_prompt_version: str = "m6.1-v1"
    ai_schema_version: str = "m6.1-v1"
    ai_ollama_url: str = "http://localhost:11434"

    @field_validator(
        "ai_provider", "ai_model", "ai_api_key", "ai_groq_api_key",
        "ai_ollama_url", mode="before"
    )
    @classmethod
    def _clean_ai_strings(cls, v):
        # .env typos that are invisible in logs but fatal in URLs:
        # trailing spaces and pasted surrounding quotes. These fields
        # never legitimately start/end with quotes or whitespace.
        if isinstance(v, str):
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
                v = v[1:-1].strip()
        return v


settings = Settings()
