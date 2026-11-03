"""Builders shared by the contract-adapter tests. No network, no clock."""

from datetime import UTC, datetime
from typing import Any

import pytest

from guardian.adapters.contract import GenericMapper, MappingProfile, load_profile

FIXED = datetime(2026, 11, 3, 10, 0, 0, tzinfo=UTC)
FIXED_ISO = "2026-11-03T10:00:00Z"


def envelope(payload: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """An envelope as it leaves security.check_inbound (signature already verified)."""
    body: dict[str, Any] = {
        "schema_version": "1.0",
        "event_id": "EVT-1",
        "seq": 1,
        "timestamp": FIXED_ISO,
        "source": {"layer": "twin", "device_id": "S01"},
        "zone_id": "PORT",
        "type": "sensor_reading",
        "payload": payload,
    }
    body.update(overrides)
    return body


def measurement_profile(**fields: Any) -> MappingProfile:
    data: dict[str, Any] = {"profile_id": "test-v1", "schema_id": "test-v1", "event_kind": "measurement"}
    data.update(fields)
    return load_profile(data)


@pytest.fixture
def mapper() -> GenericMapper:
    return GenericMapper()
