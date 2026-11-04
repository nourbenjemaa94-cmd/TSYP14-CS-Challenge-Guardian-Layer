"""C13: unauthenticated timeline exposure is restricted by environment/mode."""

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from guardian.main import app


def _assert_timeline_refused() -> None:
    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws/timeline"):
                pass


def test_c13_production_demo_rejects_unauthenticated_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIAN_ENV", "production")
    monkeypatch.setenv("GUARDIAN_TIMELINE_MODE", "demo")

    _assert_timeline_refused()


def test_c13_local_loopback_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIAN_ENV", "development")
    monkeypatch.setenv("GUARDIAN_TIMELINE_MODE", "local")

    with TestClient(app) as client:
        with client.websocket_connect("/ws/timeline") as websocket:
            websocket.send_text("ping")
            assert websocket.receive_text() == "pong"


def test_c13_disabled_rejects_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIAN_ENV", "development")
    monkeypatch.setenv("GUARDIAN_TIMELINE_MODE", "disabled")

    _assert_timeline_refused()
