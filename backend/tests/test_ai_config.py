"""AI configuration wiring: .env anchor and env-var precedence."""

from pathlib import Path


def test_env_file_anchored_to_backend_dir():
    from app.core.config import Settings

    env_file = Settings.model_config.get("env_file")
    assert env_file is not None
    # Must resolve inside the backend directory regardless of CWD,
    # so launching from the repo root can't silently drop AI_* settings.
    assert Path(env_file).parent.name == "backend"
    assert Path(env_file).name == ".env"


def test_env_vars_take_precedence(monkeypatch):
    from app.core.config import Settings

    monkeypatch.setenv("AI_PROVIDER", "mock")
    monkeypatch.setenv("AI_MODEL", "test-model")
    s = Settings()
    assert s.ai_provider == "mock"
    assert s.ai_model == "test-model"


def test_ai_strings_cleaned_of_invisible_typo_chars():
    from app.core.config import Settings

    s = Settings(
        AI_PROVIDER="  gemini ",
        AI_MODEL='"gemini-2.5-flash" ',
        AI_API_KEY="  secret-key  ",
        AI_OLLAMA_URL=" http://localhost:11434/ ",
    )
    assert s.ai_provider == "gemini"
    assert s.ai_model == "gemini-2.5-flash"
    assert s.ai_api_key == "secret-key"
    assert s.ai_ollama_url == "http://localhost:11434/"


def test_defaults_keep_ai_optional(monkeypatch, tmp_path):
    from app.core.config import Settings

    for var in ("AI_PROVIDER", "AI_MODEL", "AI_API_KEY", "AI_GROQ_API_KEY",
                "AI_TIMEOUT", "AI_PROMPT_VERSION", "AI_SCHEMA_VERSION",
                "AI_OLLAMA_URL"):
        monkeypatch.delenv(var, raising=False)
    # Point at an empty dir so no .env file is found: only defaults apply.
    monkeypatch.chdir(tmp_path)
    s = Settings(_env_file=str(tmp_path / ".env"))
    assert s.ai_provider == "disabled"
    assert s.ai_api_key == ""
