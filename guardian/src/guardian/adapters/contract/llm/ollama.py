"""HTTP client for a local Ollama instance.

Never logs prompt text, response bodies, or model output. Failures raise
``ProviderUnavailable`` (not ``MappingError``) so the live path cannot treat
a model outage as a mapping error.
"""

from __future__ import annotations

import json
from typing import Any

import httpx


class ProviderUnavailable(Exception):
    """The local model did not return a usable response."""


class OllamaClient:
    """Thin Ollama HTTP client with one retry on transport or 5xx errors."""

    def __init__(
        self,
        base_url: str,
        model: str,
        embed_model: str,
        timeout_seconds: float,
        num_ctx: int,
        num_gpu: int,
        transport: httpx.BaseTransport | None = None,
        *,
        client_factory: type[httpx.Client] = httpx.Client,
    ) -> None:
        if not base_url.strip():
            raise ValueError("base_url must not be empty")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.embed_model = embed_model
        self.timeout_seconds = timeout_seconds
        self.num_ctx = num_ctx
        self.num_gpu = num_gpu
        self._transport = transport
        self._client_factory = client_factory

    def chat_json(self, prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        """POST /api/chat and return the parsed JSON object in ``message.content``."""
        options: dict[str, Any] = {"temperature": 0, "num_ctx": self.num_ctx}
        if self.num_gpu >= 0:
            options["num_gpu"] = self.num_gpu
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "format": schema,
            "options": options,
            "keep_alive": "10m",
        }
        body = self._request("POST", "/api/chat", json_body=payload)
        message = body.get("message") if isinstance(body, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        parsed = _parse_json_object(content)
        if parsed is None:
            raise ProviderUnavailable("Ollama chat reply was not a JSON object.")
        return parsed

    def embed(self, text: str) -> list[float]:
        """POST /api/embed and return one embedding vector."""
        body = self._request("POST", "/api/embed", json_body={"model": self.embed_model, "input": text})
        embeddings = body.get("embeddings") if isinstance(body, dict) else None
        if (
            isinstance(embeddings, list)
            and embeddings
            and isinstance(embeddings[0], list)
            and all(isinstance(item, (int, float)) for item in embeddings[0])
        ):
            return [float(item) for item in embeddings[0]]
        raise ProviderUnavailable("Ollama embed reply did not contain a vector.")

    def tags(self) -> list[str]:
        """GET /api/tags and return installed model names."""
        body = self._request("GET", "/api/tags")
        models = body.get("models") if isinstance(body, dict) else None
        if not isinstance(models, list):
            raise ProviderUnavailable("Ollama tags reply did not list models.")
        names: list[str] = []
        for item in models:
            if isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"]:
                names.append(item["name"])
        return names

    def _request(self, method: str, path: str, *, json_body: dict[str, Any] | None = None) -> dict[str, Any]:
        last_error = "Ollama request failed."
        for _attempt in range(2):
            try:
                with self._client_factory(
                    base_url=self.base_url,
                    timeout=self.timeout_seconds,
                    transport=self._transport,
                ) as client:
                    response = client.request(method, path, json=json_body)
            except httpx.TransportError:
                last_error = "Ollama is unreachable."
                continue
            if response.status_code >= 500:
                last_error = "Ollama returned a server error."
                continue
            if response.status_code >= 400:
                raise ProviderUnavailable("Ollama rejected the request.")
            try:
                body = response.json()
            except ValueError:
                raise ProviderUnavailable("Ollama reply was not JSON.") from None
            if not isinstance(body, dict):
                raise ProviderUnavailable("Ollama reply was not a JSON object.")
            return body
        raise ProviderUnavailable(last_error)


def _parse_json_object(content: object) -> dict[str, Any] | None:
    if isinstance(content, dict):
        return content
    if not isinstance(content, str):
        return None
    try:
        parsed = json.loads(content)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None
