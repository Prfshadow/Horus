"""LLMProvider abstraction — provider-agnostic, httpx-based."""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Any

import httpx


@dataclass
class ProviderRequest:
    prompt: str
    model: str
    json_schema: Optional[dict] = None
    timeout_s: int = 30
    max_output_tokens: int = 2000
    temperature: float = 0.2


@dataclass
class ProviderResponse:
    raw_text: str
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    latency_ms: Optional[int] = None


class ProviderError(Exception):
    def __init__(self, code: str, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class LLMProvider(ABC):
    @abstractmethod
    async def generate(self, request: ProviderRequest) -> ProviderResponse:
        pass


class MockProvider(LLMProvider):
    """Deterministic mock for tests."""

    def __init__(self, response_text: Optional[str] = None):
        self.response_text = response_text or '{"summary":"mock summary","observations":[{"statement":"mock fact","type":"fact","evidence_ids":["incident:1"]}],"supporting_evidence":[],"alternative_explanations":[],"recommended_steps":[],"limitations":[]}'

    async def generate(self, request: ProviderRequest) -> ProviderResponse:
        return ProviderResponse(raw_text=self.response_text, latency_ms=10)


class TimeoutProvider(LLMProvider):
    async def generate(self, request: ProviderRequest) -> ProviderResponse:
        raise ProviderError("timeout", "Provider timed out", status_code=504)


class UnavailableProvider(LLMProvider):
    async def generate(self, request: ProviderRequest) -> ProviderResponse:
        raise ProviderError("unavailable", "Provider unavailable", status_code=503)


def _provider_error_detail(response: httpx.Response) -> str:
    """Extract a provider's error reason, truncated. Error bodies carry
    status details only — never credentials — so this is safe to log
    and return. (Gemini and Groq both use {"error": {"message": ...}}.)"""
    try:
        data = response.json()
    except Exception:
        return ""
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict) and isinstance(err.get("message"), str):
            return err["message"][:200]
    return ""


class GeminiProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "gemini-2.5-flash"):
        self.api_key = api_key
        self.model = model

    async def generate(self, request: ProviderRequest) -> ProviderResponse:
        if not self.api_key:
            raise ProviderError("authentication", "Gemini API key missing", status_code=401)
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{request.model}:generateContent?key={self.api_key}"
        payload = {
            "contents": [{"parts": [{"text": request.prompt}]}],
            "generationConfig": {"temperature": request.temperature, "maxOutputTokens": request.max_output_tokens},
        }
        start = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=request.timeout_s) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code == 404:
                    # Model availability can differ between Google's API
                    # versions: retry the same model once on the stable v1
                    # endpoint before reporting it as not found.
                    v1_url = url.replace("/v1beta/", "/v1/", 1)
                    if v1_url != url:
                        resp = await client.post(v1_url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                # Extract text
                try:
                    raw = data["candidates"][0]["content"]["parts"][0]["text"]
                except Exception as e:
                    raise ProviderError("malformed_response", f"Gemini response parse failed: {e}")
                latency = int((time.monotonic() - start) * 1000)
                return ProviderResponse(raw_text=raw, latency_ms=latency)
        except httpx.TimeoutException:
            raise ProviderError("timeout", "Gemini timeout", status_code=504)
        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            reason = _provider_error_detail(e.response)
            suffix = f": {reason}" if reason else ""
            # Gemini reports bad/expired API keys as 400 (and 401/403 for
            # other auth problems) — these are authentication failures, not
            # malformed model output, so they must stay distinguishable.
            if status in (400, 401, 403):
                code = "authentication"
            elif status == 429:
                code = "rate_limit"
            elif status == 404:
                # Unknown model name / endpoint — a configuration problem
                # (check AI_MODEL), not malformed model output.
                raise ProviderError(
                    "unavailable",
                    f"Gemini model not found (HTTP 404){suffix} — check AI_MODEL",
                    status_code=status,
                )
            elif status >= 500:
                code = "unavailable"
            else:
                code = "malformed_response"
            # Never include str(e): it embeds the request URL, which carries
            # the API key as a query parameter. Report status + Google's
            # reason phrase only.
            raise ProviderError(code, f"Gemini HTTP {status}{suffix}", status_code=status)
        except ProviderError:
            raise
        except Exception:
            # Generic message on purpose: raw exception text can embed the
            # request URL, which carries the API key as a query parameter.
            raise ProviderError("unavailable", "Gemini request failed")


class OllamaProvider(LLMProvider):
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.1:8b"):
        self.base_url = base_url.rstrip("/")
        self.model = model

    async def generate(self, request: ProviderRequest) -> ProviderResponse:
        url = f"{self.base_url}/api/generate"
        payload = {"model": request.model, "prompt": request.prompt, "stream": False, "options": {"temperature": request.temperature, "num_predict": request.max_output_tokens}}
        start = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=request.timeout_s) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                raw = data.get("response") or data.get("text") or ""
                if not raw:
                    raise ProviderError("malformed_response", "Ollama empty response")
                latency = int((time.monotonic() - start) * 1000)
                return ProviderResponse(raw_text=raw, latency_ms=latency)
        except httpx.TimeoutException:
            raise ProviderError("timeout", "Ollama timeout", status_code=504)
        except httpx.HTTPStatusError as e:
            raise ProviderError("unavailable", str(e), status_code=e.response.status_code)
        except ProviderError:
            raise
        except Exception as e:
            raise ProviderError("unavailable", str(e))


class GroqProvider(LLMProvider):
    """Groq via its OpenAI-compatible chat-completions API.

    The key travels in the Authorization header (never in the URL).
    Requests JSON mode so responses parse cleanly downstream.
    """

    BASE_URL = "https://api.groq.com/openai/v1"

    def __init__(self, api_key: str, model: str = "openai/gpt-oss-120b"):
        self.api_key = api_key
        self.model = model

    async def generate(self, request: ProviderRequest) -> ProviderResponse:
        if not self.api_key:
            raise ProviderError("authentication", "Groq API key missing", status_code=401)
        url = f"{self.BASE_URL}/chat/completions"
        payload = {
            "model": request.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a read-only security investigation assistant. Return ONLY JSON.",
                },
                {"role": "user", "content": request.prompt},
            ],
            "temperature": request.temperature,
            "max_tokens": request.max_output_tokens,
            "response_format": {"type": "json_object"},
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        start = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=request.timeout_s) as client:
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                try:
                    raw = data["choices"][0]["message"]["content"]
                except Exception:
                    raise ProviderError("malformed_response", "Groq response has no message content")
                if not isinstance(raw, str) or not raw.strip():
                    raise ProviderError("malformed_response", "Groq empty response")
                latency = int((time.monotonic() - start) * 1000)
                return ProviderResponse(raw_text=raw, latency_ms=latency)
        except httpx.TimeoutException:
            raise ProviderError("timeout", "Groq timeout", status_code=504)
        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            reason = _provider_error_detail(e.response)
            suffix = f": {reason}" if reason else ""
            if status in (400, 401, 403):
                code = "authentication"
            elif status == 429:
                code = "rate_limit"
            elif status == 404:
                raise ProviderError(
                    "unavailable",
                    f"Groq model not found (HTTP 404){suffix} — check AI_MODEL",
                    status_code=status,
                )
            elif status >= 500:
                code = "unavailable"
            else:
                code = "malformed_response"
            # Status + provider reason only; the Bearer key lives in headers
            # and is never stringified into the message.
            raise ProviderError(code, f"Groq HTTP {status}{suffix}", status_code=status)
        except ProviderError:
            raise
        except Exception:
            raise ProviderError("unavailable", "Groq request failed")


def get_provider() -> LLMProvider:
    """Factory based on settings."""
    from app.core.config import settings
    provider = settings.ai_provider.lower()
    if provider == "mock":
        return MockProvider()
    if provider == "gemini":
        return GeminiProvider(api_key=settings.ai_api_key, model=settings.ai_model)
    if provider == "groq":
        return GroqProvider(api_key=settings.ai_groq_api_key, model=settings.ai_model)
    if provider == "ollama":
        return OllamaProvider(base_url=settings.ai_ollama_url, model=settings.ai_model)
    if provider == "disabled":
        raise ProviderError("unavailable", "AI provider disabled", status_code=503)
    raise ProviderError("unavailable", f"Unknown AI_PROVIDER: {provider}", status_code=503)
