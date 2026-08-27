from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class ModelProvider(Protocol):
    """Contract used by attack evaluators to obtain a model response."""

    name: str

    def complete(self, prompt: str, system_prompt: str | None = None) -> str:
        ...

    def health(self) -> dict[str, str | bool]:
        ...


@dataclass(frozen=True)
class RuleBasedProvider:
    """Offline provider used by the lab when no model is configured."""

    name: str = "rule-based"

    def complete(self, prompt: str, system_prompt: str | None = None) -> str:
        return ""

    def health(self) -> dict[str, str | bool]:
        return {"provider": self.name, "available": True, "status": "offline"}


@dataclass(frozen=True)
class OllamaProvider:
    """Small Ollama HTTP adapter; the caller owns response evaluation."""

    base_url: str = "http://localhost:11434"
    model: str = "llama3"
    timeout_seconds: float = 30.0
    name: str = "ollama"

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Ollama base_url must be an absolute HTTP(S) URL.")

    def complete(self, prompt: str, system_prompt: str | None = None) -> str:
        request_body: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        if system_prompt:
            request_body["system"] = system_prompt
        request = Request(
            f"{self.base_url.rstrip('/')}/api/generate",
            data=json.dumps(request_body).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:  # nosec B310
                payload = json.load(response)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f"Ollama request failed: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError("Ollama returned invalid JSON.") from exc

        generated = payload.get("response")
        if not isinstance(generated, str):
            raise RuntimeError("Ollama response did not contain a text response.")
        return generated

    def health(self) -> dict[str, str | bool]:
        request = Request(
            f"{self.base_url.rstrip('/')}/api/tags",
            headers={"Accept": "application/json"},
            method="GET",
        )
        try:
            with urlopen(request, timeout=min(self.timeout_seconds, 5.0)) as response:  # nosec B310
                if response.status < 200 or response.status >= 300:
                    raise RuntimeError(f"HTTP {response.status}")
                json.load(response)
        except (HTTPError, URLError, TimeoutError, OSError, RuntimeError, json.JSONDecodeError) as exc:
            return {"provider": self.name, "available": False, "status": "offline", "detail": str(exc)}
        return {"provider": self.name, "available": True, "status": "online"}


def build_provider() -> ModelProvider:
    provider = os.getenv("MODEL_PROVIDER", "rule-based").lower()
    if provider == "ollama":
        return OllamaProvider(
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            model=os.getenv("MODEL_NAME", "llama3"),
        )
    if provider in {"rule-based", "rules", "offline"}:
        return RuleBasedProvider()
    raise ValueError(f"Unsupported model provider: {provider}")