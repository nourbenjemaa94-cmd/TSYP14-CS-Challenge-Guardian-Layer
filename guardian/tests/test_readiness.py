"""Liveness/readiness tests for the production composition."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from guardian import main
from guardian.adapters.communication.mqtt import MqttAdapter

KEYS = {
    "GUARDIAN_HMAC_KEY_TWIN": "t" * 32,
    "GUARDIAN_HMAC_KEY_BRAIN": "b" * 32,
    "GUARDIAN_HMAC_KEY_GUARDIAN": "g" * 32,
}


@pytest.fixture(autouse=True)
def clean_composition(monkeypatch: pytest.MonkeyPatch):
    previous_pipeline = main._pipeline
    previous_signer = main._outbound_signer
    previous_error = main._startup_error
    previous_cache = main._llm_cache
    previous_transport = main._llm_transport
    main._pipeline = None
    main._outbound_signer = None
    main._startup_error = None
    main._llm_cache = None
    main._llm_transport = None
    monkeypatch.delenv("GUARDIAN_CONFIG", raising=False)
    monkeypatch.setenv("GUARDIAN_LLM_PROVIDER", "none")
    yield
    main._pipeline = previous_pipeline
    main._outbound_signer = previous_signer
    main._startup_error = previous_error
    main._llm_cache = previous_cache
    main._llm_transport = previous_transport


def set_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in KEYS.items():
        monkeypatch.setenv(name, value)


def test_health_is_liveness_but_missing_keys_make_readiness_fail(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)  # no developer .env in the working directory
    for name in KEYS:
        monkeypatch.delenv(name, raising=False)

    with TestClient(main.app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["llm"] == "disabled"
        response = client.get("/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "NOT_READY"


def test_invalid_configuration_prevents_readiness(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    set_keys(monkeypatch)
    config_path = tmp_path / "invalid.yaml"
    config_path.write_text("server:\n  port: 70000\n", encoding="utf-8")
    monkeypatch.setenv("GUARDIAN_CONFIG", str(config_path))

    response = asyncio.run(main.readiness_check())

    assert response.status_code == 503
    assert response.body


def test_unavailable_mqtt_broker_keeps_liveness_but_blocks_readiness(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    set_keys(monkeypatch)
    config_path = tmp_path / "mqtt.yaml"
    config_path.write_text(
        "partners:\n  twin:\n    adapter: mqtt\n    mqtt:\n      host: unavailable-broker\n      port: 1883\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GUARDIAN_CONFIG", str(config_path))

    def unavailable(self: MqttAdapter) -> None:
        raise ConnectionError("broker unavailable")

    monkeypatch.setattr(MqttAdapter, "start", unavailable)
    with TestClient(main.app) as client:
        assert client.get("/health").status_code == 200
        response = client.get("/ready")

    assert response.status_code == 503
    assert response.json()["reason"] == "STARTUP_FAILED"
    assert response.json()["checks"]["mqtt_connection"] is False


def test_mqtt_readiness_tracks_connection_subscription_cutoff_and_reconnect(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    set_keys(monkeypatch)
    config_path = tmp_path / "mqtt.yaml"
    config_path.write_text(
        "partners:\n  twin:\n    adapter: mqtt\n    mqtt:\n      host: broker\n      port: 1883\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GUARDIAN_CONFIG", str(config_path))
    instances: list[MqttAdapter] = []

    def start(self: MqttAdapter) -> None:
        instances.append(self)
        self._running = True

    monkeypatch.setattr(MqttAdapter, "start", start)
    with TestClient(main.app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 503

        adapter = instances[-1]
        adapter._connected = True
        adapter._pending_subscribe_mid = 1
        assert adapter.subscribed is False
        assert client.get("/ready").status_code == 503

        adapter._on_subscribe(adapter.client, None, 1, [1], None)
        assert client.get("/ready").status_code == 200

        adapter._connected = False
        adapter._subscribed = False
        adapter._pending_subscribe_mid = None
        assert client.get("/ready").status_code == 503

        adapter._connected = True
        adapter._pending_subscribe_mid = 2
        adapter._on_subscribe(adapter.client, None, 2, [1], None)
        assert client.get("/ready").status_code == 200


def test_complete_production_composition_is_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    set_keys(monkeypatch)

    with TestClient(main.app) as client:
        response = client.get("/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "READY"
    assert all(body["checks"].values())


def _llm_app(monkeypatch: pytest.MonkeyPatch, handler) -> TestClient:
    monkeypatch.setenv("GUARDIAN_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("GUARDIAN_LLM_URL", "http://ollama.test")
    main._llm_transport = httpx.MockTransport(handler)
    return TestClient(main.app)


def test_health_llm_is_reachable_when_tags_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        assert request.url.path == "/api/tags"
        return httpx.Response(200, json={"models": []})

    with _llm_app(monkeypatch, handler) as client:
        first = client.get("/health")
        second = client.get("/health")

    assert first.json()["llm"] == "reachable"
    assert second.json()["llm"] == "reachable"
    assert hits["n"] == 1


def test_health_llm_is_unreachable_on_server_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "busy"})

    with _llm_app(monkeypatch, handler) as client:
        assert client.get("/health").json()["llm"] == "unreachable"


def test_health_llm_cache_expires_after_thirty_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    hits = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        return httpx.Response(200, json={"models": []})

    monkeypatch.setenv("GUARDIAN_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("GUARDIAN_LLM_URL", "http://ollama.test")
    main._llm_transport = httpx.MockTransport(handler)
    assert main._llm_status(now=100.0) == "reachable"
    assert main._llm_status(now=129.0) == "reachable"
    assert main._llm_status(now=130.1) == "reachable"
    assert hits["n"] == 2


def test_timeline_is_closed_when_exposure_is_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIAN_TIMELINE_MODE", "disabled")

    with TestClient(main.app) as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws/timeline"):
                pass
