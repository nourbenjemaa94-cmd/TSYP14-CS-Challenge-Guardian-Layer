"""Shared builders for security tests. Clocks are fake. Keys are obvious fakes."""

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient

from guardian.config import load_config, repo_root
from guardian.main import create_app
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


def build_client(
    clock: FakeTime | None = None,
    *,
    core: object | None = None,
    **setting_overrides: Any,
) -> tuple[TestClient, Any, FakeTime]:
    time = clock or FakeTime()
    app = create_app(
        settings=make_settings(**setting_overrides),
        config=load_config(repo_root() / "config.example.yaml", environ={}),
        clock=time.clock,
        monotonic=time.monotonic,
        core=core,
    )
    return TestClient(app), app, time
