"""Offline Ollama client tests. No network: every call uses MockTransport."""

from __future__ import annotations

import json

import httpx
import pytest

from guardian.adapters.contract.llm.ollama import OllamaClient, ProviderUnavailable


def client(handler, *, num_gpu: int = 0) -> OllamaClient:
    return OllamaClient(
        base_url="http://ollama.test",
        model="qwen2.5:3b",
        embed_model="nomic-embed-text",
        timeout_seconds=2,
        num_ctx=2048,
        num_gpu=num_gpu,
        transport=httpx.MockTransport(handler),
    )


def json_response(payload: object, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=payload)


def test_chat_json_posts_schema_and_returns_the_object() -> None:
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return json_response({"message": {"content": '{"ok": true}'}})

    result = client(handler).chat_json("hello", {"type": "object"})

    assert result == {"ok": True}
    assert seen[0]["model"] == "qwen2.5:3b"
    assert seen[0]["stream"] is False
    assert seen[0]["format"] == {"type": "object"}
    assert seen[0]["options"] == {"temperature": 0, "num_ctx": 2048, "num_gpu": 0}
    assert seen[0]["keep_alive"] == "10m"


def test_num_gpu_is_omitted_when_negative() -> None:
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return json_response({"message": {"content": "{}"}})

    client(handler, num_gpu=-1).chat_json("hello", {"type": "object"})

    assert "num_gpu" not in seen[0]["options"]
    assert seen[0]["options"]["num_ctx"] == 2048


def test_chat_retries_once_then_succeeds() -> None:
    attempts = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] == 1:
            return json_response({"error": "busy"}, status=503)
        return json_response({"message": {"content": '{"ok": true}'}})

    assert client(handler).chat_json("hello", {"type": "object"}) == {"ok": True}
    assert attempts["n"] == 2


def test_chat_retries_once_then_raises() -> None:
    attempts = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        raise httpx.ConnectError("refused")

    with pytest.raises(ProviderUnavailable, match="unreachable"):
        client(handler).chat_json("hello", {"type": "object"})
    assert attempts["n"] == 2


def test_malformed_chat_content_is_unavailable() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return json_response({"message": {"content": "not-json"}})

    with pytest.raises(ProviderUnavailable, match="not a JSON object"):
        client(handler).chat_json("hello", {"type": "object"})


def test_embed_returns_the_first_vector() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["model"] == "nomic-embed-text"
        assert body["input"] == "water_level"
        return json_response({"embeddings": [[0.1, 0.2, 0.3]]})

    assert client(handler).embed("water_level") == [0.1, 0.2, 0.3]


def test_tags_lists_model_names() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/api/tags"
        return json_response({"models": [{"name": "qwen2.5:3b"}, {"name": "nomic-embed-text"}]})

    assert client(handler).tags() == ["qwen2.5:3b", "nomic-embed-text"]


def test_contract_package_does_not_export_the_client() -> None:
    import guardian.adapters.contract as contract

    assert "OllamaClient" not in contract.__all__
    assert not hasattr(contract, "OllamaClient")
