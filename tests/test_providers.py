import json

import pytest

from engine.providers import OllamaProvider, RuleBasedProvider, build_provider


def test_rule_based_provider_is_offline_default(monkeypatch):
    monkeypatch.delenv("MODEL_PROVIDER", raising=False)

    provider = build_provider()

    assert isinstance(provider, RuleBasedProvider)
    assert provider.complete("test") == ""


def test_ollama_provider_builds_request_and_returns_response(monkeypatch):
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"response": "safe answer"}).encode()

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("engine.providers.urlopen", fake_urlopen)
    result = OllamaProvider(model="llama3").complete("hello", "be safe")

    assert result == "safe answer"
    assert captured["timeout"] == 30.0
    body = json.loads(captured["request"].data)
    assert body["model"] == "llama3"
    assert body["system"] == "be safe"
    assert body["stream"] is False


def test_ollama_provider_rejects_invalid_url():
    with pytest.raises(ValueError, match="absolute HTTP"):
        OllamaProvider(base_url="localhost:11434")


def test_ollama_health_returns_offline_when_service_is_unavailable(monkeypatch):
    def unavailable(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr("engine.providers.urlopen", unavailable)

    result = OllamaProvider().health()

    assert result["available"] is False
    assert result["status"] == "offline"