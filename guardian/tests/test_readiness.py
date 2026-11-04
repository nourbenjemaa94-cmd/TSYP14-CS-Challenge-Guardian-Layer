"""Liveness/readiness tests for the production composition."""

from __future__ import annotations

import asyncio

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
    main._pipeline = None
    main._outbound_signer = None
    main._startup_error = None
    monkeypatch.delenv("GUARDIAN_CONFIG", raising=False)
    yield
    main._pipeline = previous_pipeline
    main._outbound_signer = previous_signer
    main._startup_error = previous_error


def set_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in KEYS.items():
        monkeypatch.setenv(name, value)


def test_health_is_liveness_but_missing_keys_make_readiness_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in KEYS:
        monkeypatch.delenv(name, raising=False)

    with TestClient(main.app) as client:
        assert client.get("/health").status_code == 200
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


def test_timeline_is_closed_when_exposure_is_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIAN_TIMELINE_MODE", "disabled")

    with TestClient(main.app) as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws/timeline"):
                pass
