"""Shared builders for security tests. Clocks are fake. Keys are obvious fakes."""

import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from guardian.security.authentication import sign_envelope
from guardian.security.freshness import format_timestamp
from guardian.security.gate import SecurityGate, SecuritySettings

TWIN_KEY = "t" * 32
BRAIN_KEY = "b" * 32
GUARDIAN_KEY = "g" * 32
FIXED = datetime(2026, 11, 8, 12, 0, 0, tzinfo=UTC)


class FakeTime:
    """Wall clock and monotonic clock that move only when a test says so."""

    def __init__(self, start: datetime | None = None) -> None:
        self.wall = start or FIXED
        self.mono = 0.0

    def clock(self) -> datetime:
        return self.wall

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        self.wall = self.wall + timedelta(seconds=seconds)

    def stamp(self, delta_seconds: float = 0) -> str:
        return format_timestamp(self.wall + timedelta(seconds=delta_seconds))


def make_settings(**overrides: Any) -> SecuritySettings:
    values: dict[str, Any] = {
        "hmac_key_twin": TWIN_KEY,
        "hmac_key_brain": BRAIN_KEY,
        "hmac_key_guardian": GUARDIAN_KEY,
    }
    values.update(overrides)
    return SecuritySettings(**values)


def make_gate(clock: FakeTime | None = None, **overrides: Any) -> SecurityGate:
    time = clock or FakeTime()
    max_sources = int(overrides.pop("max_sources", 10_000))
    return SecurityGate(
        make_settings(**overrides),
        clock=time.clock,
        monotonic=time.monotonic,
        max_sources=max_sources,
    )


def reading(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema_version": "1.0",
        "schema_id": "twin-canonical-v1",
        "event_id": "evt-8f2c1a",
        "seq": 1,
        "timestamp": format_timestamp(FIXED),
        "source": {"layer": "twin", "device_id": "S01"},
        "zone_id": "PORT",
        "type": "sensor_reading",
        "payload": {"metric": "water_level", "value": 180, "unit": "cm"},
    }
    for key, value in overrides.items():
        if key == "source" and isinstance(value, dict):
            merged = dict(body["source"])
            merged.update(value)
            body["source"] = merged
        else:
            body[key] = value
    return body


def signed(body: dict[str, Any], key: str = TWIN_KEY) -> dict[str, Any]:
    return sign_envelope(body, key)


def raw(body: dict[str, Any]) -> bytes:
    return json.dumps(body).encode("utf-8")


@dataclass
class LiveApp:
    """Production app under test: the HTTP client plus what left Guardian."""

    client: TestClient
    sent_to_brain: list[dict[str, Any]] = field(default_factory=list)
    path: str = "/api/v1/telemetry"

    def post(self, body: dict[str, Any] | bytes):
        content = body if isinstance(body, bytes) else raw(body)
        return self.client.post(self.path, content=content)


@contextmanager
def make_client(
    monkeypatch: pytest.MonkeyPatch,
    workdir: Path,
    *,
    environ: dict[str, str] | None = None,
) -> Iterator[LiveApp]:
    """Run ``guardian.main.app`` with fake keys and no developer ``.env``.

    The working directory is moved to ``workdir`` (a temp dir) so a local
    ``guardian/.env`` or ``guardian/config.yaml`` cannot leak into the test;
    HMAC keys come from the fake constants above. Brain delivery is recorded
    instead of sent. Module-level composition state is restored on exit.
    """
    from guardian import main
    from guardian.adapters.communication.brain import RestBrainOutputAdapter
    from guardian.audit.event_store import default_event_store

    monkeypatch.chdir(workdir)
    monkeypatch.delenv("GUARDIAN_CONFIG", raising=False)
    monkeypatch.setenv("GUARDIAN_HMAC_KEY_TWIN", TWIN_KEY)
    monkeypatch.setenv("GUARDIAN_HMAC_KEY_BRAIN", BRAIN_KEY)
    monkeypatch.setenv("GUARDIAN_HMAC_KEY_GUARDIAN", GUARDIAN_KEY)
    for name, value in (environ or {}).items():
        monkeypatch.setenv(name, value)

    sent: list[dict[str, Any]] = []

    async def record(_self: Any, payload: dict[str, Any]) -> bool:
        sent.append(payload)
        return True

    monkeypatch.setattr(RestBrainOutputAdapter, "send_to_brain", record)
    previous = (main._pipeline, main._outbound_signer, main._startup_error)
    main._pipeline, main._outbound_signer, main._startup_error = None, None, None
    default_event_store.clear()
    try:
        with TestClient(main.app) as client:
            yield LiveApp(client=client, sent_to_brain=sent)
    finally:
        default_event_store.clear()
        main._pipeline, main._outbound_signer, main._startup_error = previous
