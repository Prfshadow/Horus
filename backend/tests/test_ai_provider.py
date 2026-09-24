import asyncio
import pytest
from app.ai.provider import MockProvider, TimeoutProvider, UnavailableProvider, ProviderError, GeminiProvider, GroqProvider, OllamaProvider, ProviderRequest

def test_successful_provider():
    async def run():
        p = MockProvider(response_text='{"summary":"s","observations":[{"statement":"fact","type":"fact","evidence_ids":["incident:1"]}],"supporting_evidence":[],"alternative_explanations":[],"recommended_steps":[],"limitations":[]}')
        req = ProviderRequest(prompt="hello", model="mock", json_schema=None)
        resp = await p.generate(req)
        assert "summary" in resp.raw_text
    asyncio.run(run())

def test_timeout():
    async def run():
        p = TimeoutProvider()
        req = ProviderRequest(prompt="hello", model="x")
        try:
            await p.generate(req)
            assert False, "should raise"
        except ProviderError as e:
            assert e.code == "timeout"
            assert e.status_code == 504
    asyncio.run(run())

def test_unavailable():
    async def run():
        p = UnavailableProvider()
        req = ProviderRequest(prompt="hello", model="x")
        try:
            await p.generate(req)
            assert False
        except ProviderError as e:
            assert e.code == "unavailable"
    asyncio.run(run())

def test_gemini_missing_key():
    async def run():
        p = GeminiProvider(api_key="", model="gemini-2.5-flash")
        req = ProviderRequest(prompt="hello", model="gemini-2.5-flash")
        try:
            await p.generate(req)
            assert False
        except ProviderError as e:
            assert e.code == "authentication"
    asyncio.run(run())

def test_gemini_http_status_mapping(monkeypatch):
    import httpx

    class _StubClient:
        def __init__(self, status):
            self._status = status

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, json=None):
            return httpx.Response(
                self._status,
                request=httpx.Request("POST", url),
                json={"error": {"message": "stubbed"}},
            )

    async def run_with_status(status):
        p = GeminiProvider(api_key="k", model="m")
        req = ProviderRequest(prompt="hello", model="m")
        monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _StubClient(status))
        try:
            await p.generate(req)
            assert False, f"status {status} should raise"
        except ProviderError as e:
            return e

    # Gemini reports bad keys as 400 — must be authentication, not malformed output
    for status in (400, 401, 403):
        err = asyncio.run(run_with_status(status))
        assert err.code == "authentication", f"status {status} -> {err.code}"
        assert err.status_code == status
    err = asyncio.run(run_with_status(429))
    assert err.code == "rate_limit"
    err = asyncio.run(run_with_status(500))
    assert err.code == "unavailable"
    err = asyncio.run(run_with_status(422))
    assert err.code == "malformed_response"


def test_gemini_404_is_config_error_not_malformed(monkeypatch):
    import httpx

    class _StubClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, json=None):
            return httpx.Response(
                404,
                request=httpx.Request("POST", url),
                json={"error": {"message": "models/m is not found for API version v1beta"}},
            )

    async def run():
        p = GeminiProvider(api_key="k", model="m")
        req = ProviderRequest(prompt="hello", model="m")
        monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _StubClient())
        try:
            await p.generate(req)
            assert False, "should raise"
        except ProviderError as e:
            return e

    err = asyncio.run(run())
    assert err.code == "unavailable"
    assert "AI_MODEL" in str(err)
    # Google's exact reason is preserved for diagnosis.
    assert "models/m is not found" in str(err)


def test_gemini_errors_never_leak_api_key(monkeypatch):
    import httpx

    secret = "SECRET-KEY-12345"

    class _StubClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, json=None):
            assert secret in url  # key really is in the request URL
            return httpx.Response(
                400,
                request=httpx.Request("POST", url),
                json={"error": {"message": "bad key"}},
            )

    async def run():
        p = GeminiProvider(api_key=secret, model="m")
        req = ProviderRequest(prompt="hello", model="m")
        monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _StubClient())
        try:
            await p.generate(req)
            assert False, "should raise"
        except ProviderError as e:
            return e

    err = asyncio.run(run())
    assert err.code == "authentication"
    assert secret not in str(err)
    assert "key=" not in str(err).lower()


def test_gemini_falls_back_to_v1_when_v1beta_404s(monkeypatch):
    import httpx

    calls = []

    class _StubClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, json=None):
            calls.append(url)
            if "/v1beta/" in url:
                return httpx.Response(
                    404,
                    request=httpx.Request("POST", url),
                    json={"error": {"message": "not found"}},
                )
            return httpx.Response(
                200,
                request=httpx.Request("POST", url),
                json={"candidates": [{"content": {"parts": [{"text": '{"summary":"ok"}'}]}}]},
            )

    async def run():
        p = GeminiProvider(api_key="k", model="m")
        req = ProviderRequest(prompt="hello", model="m")
        monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _StubClient())
        return await p.generate(req)

    resp = asyncio.run(run())
    assert resp.raw_text == '{"summary":"ok"}'
    assert any("/v1beta/" in u for u in calls)
    assert any("/v1/" in u and "/v1beta/" not in u for u in calls)


def test_groq_missing_key():
    async def run():
        p = GroqProvider(api_key="", model="llama-3.3-70b-versatile")
        req = ProviderRequest(prompt="hello", model="llama-3.3-70b-versatile")
        try:
            await p.generate(req)
            assert False, "should raise"
        except ProviderError as e:
            return e

    err = asyncio.run(run())
    assert err.code == "authentication"


def test_groq_success_extracts_message_content(monkeypatch):
    import httpx

    seen = {}

    class _StubClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, json=None, headers=None):
            seen["url"] = url
            seen["headers"] = headers
            seen["json"] = json
            return httpx.Response(
                200,
                request=httpx.Request("POST", url),
                json={"choices": [{"message": {"content": '{"summary":"ok"}'}}]},
            )

    async def run():
        p = GroqProvider(api_key="k", model="m")
        req = ProviderRequest(prompt="hello", model="m")
        monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _StubClient())
        return await p.generate(req)

    resp = asyncio.run(run())
    assert resp.raw_text == '{"summary":"ok"}'
    assert seen["url"] == "https://api.groq.com/openai/v1/chat/completions"
    # Key travels in the header, never in the URL.
    assert "k" not in seen["url"]
    assert seen["headers"]["Authorization"] == "Bearer k"
    assert seen["json"]["response_format"] == {"type": "json_object"}


def test_groq_http_status_mapping(monkeypatch):
    import httpx

    async def run_with_status(status, body):
        class _StubClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def post(self, url, json=None, headers=None):
                return httpx.Response(
                    status, request=httpx.Request("POST", url), json=body
                )

        p = GroqProvider(api_key="k", model="m")
        req = ProviderRequest(prompt="hello", model="m")
        monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _StubClient())
        try:
            await p.generate(req)
            assert False, f"status {status} should raise"
        except ProviderError as e:
            return e

    err = asyncio.run(run_with_status(401, {"error": {"message": "invalid key"}}))
    assert err.code == "authentication"
    err = asyncio.run(run_with_status(429, {"error": {"message": "slow down"}}))
    assert err.code == "rate_limit"
    err = asyncio.run(run_with_status(404, {"error": {"message": "model not found"}}))
    assert err.code == "unavailable"
    assert "AI_MODEL" in str(err)


def test_groq_malformed_when_no_content(monkeypatch):
    import httpx

    class _StubClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, json=None, headers=None):
            return httpx.Response(
                200, request=httpx.Request("POST", url), json={"choices": []}
            )

    async def run():
        p = GroqProvider(api_key="k", model="m")
        req = ProviderRequest(prompt="hello", model="m")
        monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _StubClient())
        try:
            await p.generate(req)
            assert False, "should raise"
        except ProviderError as e:
            return e

    err = asyncio.run(run())
    assert err.code == "malformed_response"


def test_ollama_provider_instantiation():
    p = OllamaProvider(base_url="http://localhost:11434", model="llama3.1:8b")
    assert p.base_url == "http://localhost:11434"

def test_provider_interface_no_business_logic():
    # Ensure provider doesn't modify DB — just check it has no DB import
    import inspect
    src = inspect.getsource(MockProvider)
    assert "Investigation" not in src
