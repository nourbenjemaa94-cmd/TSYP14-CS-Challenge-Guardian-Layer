"""Persistent profile selection tests for authenticated Twin identities."""

from __future__ import annotations

import pytest

from guardian.adapters.contract import GenericMapper, MappingError, MappingErrorCode, ProfileRegistry, load_profile
from guardian.contracts.events import GuardianEvent


def measurement_profile(profile_id: str, schema_id: str, version: str = "1.0"):
    return load_profile(
        {
            "profile_id": profile_id,
            "schema_id": schema_id,
            "version": version,
            "event_kind": "measurement",
            "metric_value": "water_level",
            "value_path": "$.payload.value",
            "unit_path": "$.payload.unit",
        }
    )


def status_profile(profile_id: str, schema_id: str):
    return load_profile(
        {
            "profile_id": profile_id,
            "schema_id": schema_id,
            "event_kind": "status",
            "status_path": "$.payload.status",
        }
    )


def envelope(event_type: str, payload: dict, event_id: str = "evt-profile") -> dict:
    return {
        "schema_version": "1.0",
        "event_id": event_id,
        "timestamp": "2026-11-04T10:00:00.000Z",
        "source": {"layer": "twin", "device_id": "A"},
        "type": event_type,
        "payload": payload,
    }


def test_twin_a_can_select_multiple_event_types_without_crossing_profiles(tmp_path):
    registry = ProfileRegistry(tmp_path)
    water = registry.register_profile(
        measurement_profile("a-water-v1", "a-water", "1.0"),
        twin_identity="twin:A",
        event_type="water_reading",
        status="ACTIVE",
    )
    status = registry.register_profile(
        status_profile("a-status-v1", "a-status"),
        twin_identity="twin:A",
        event_type="device_status",
        status="ACTIVE",
    )

    selected_water = registry.select(
        twin_identity="twin:A",
        event_type="water_reading",
        schema_id="a-water",
        schema_version="1.0",
    )
    selected_status = registry.select(
        twin_identity="twin:A",
        event_type="device_status",
        schema_id="a-status",
        schema_version="1.0",
    )
    mapper = GenericMapper()
    numeric = mapper.map_message(envelope("water_reading", {"value": 180, "unit": "cm"}), selected_water, "twin:A")
    other = mapper.map_message(envelope("device_status", {"status": "online"}), selected_status, "twin:A")

    assert water.status == "ACTIVE"
    assert status.status == "ACTIVE"
    assert numeric[0].to_sensor_event().unit == "cm"
    assert isinstance(other[0], GuardianEvent)
    assert other[0].kind == "status"


def test_twin_b_cannot_use_twin_a_profile(tmp_path):
    registry = ProfileRegistry(tmp_path)
    registry.register_profile(
        measurement_profile("a-water-v1", "a-water"),
        twin_identity="twin:A",
        event_type="water_reading",
        status="ACTIVE",
    )

    with pytest.raises(MappingError) as exc:
        registry.select(twin_identity="twin:B", event_type="water_reading", event_id="evt-b")

    assert exc.value.code is MappingErrorCode.UNKNOWN_SCHEMA
    assert exc.value.event_id == "evt-b"


def test_schema_version_change_is_pending_until_explicit_activation_and_survives_restart(tmp_path):
    registry = ProfileRegistry(tmp_path)
    v1 = registry.register_profile(
        measurement_profile("a-water-v1", "a-water", "1.0"),
        twin_identity="twin:A",
        event_type="water_reading",
        status="ACTIVE",
    )
    v2 = registry.register_profile(
        measurement_profile("a-water-v2", "a-water", "2.0"),
        twin_identity="twin:A",
        event_type="water_reading",
        status="PENDING",
    )

    assert registry.select(
        twin_identity="twin:A",
        event_type="water_reading",
        schema_id="a-water",
        schema_version="1.0",
    ).version == "1.0"
    registry.activate(v2.fingerprint)
    assert registry.get(v1.fingerprint).status == "ACTIVE"
    assert registry.select(
        twin_identity="twin:A",
        event_type="water_reading",
        schema_id="a-water",
        schema_version="2.0",
    ).version == "2.0"

    restarted = ProfileRegistry(tmp_path)
    assert restarted.select(
        twin_identity="twin:A",
        event_type="water_reading",
        schema_id="a-water",
        schema_version="2.0",
    ).version == "2.0"


def test_pending_and_absent_profiles_are_unknown_schema(tmp_path):
    registry = ProfileRegistry(tmp_path)
    registry.register_profile(
        measurement_profile("pending", "pending-schema"),
        twin_identity="twin:A",
        event_type="water_reading",
        status="PENDING",
    )

    with pytest.raises(MappingError) as exc:
        registry.select(
            twin_identity="twin:A",
            event_type="water_reading",
            schema_id="pending-schema",
            schema_version="1.0",
        )
    assert exc.value.code is MappingErrorCode.UNKNOWN_SCHEMA


def test_ambiguous_active_profiles_fail_without_a_schema_id(tmp_path):
    registry = ProfileRegistry(tmp_path)
    registry.register_profile(
        measurement_profile("v1", "schema-v1"),
        twin_identity="twin:A",
        event_type="water_reading",
        status="ACTIVE",
    )
    registry.register_profile(
        measurement_profile("v2", "schema-v2"),
        twin_identity="twin:A",
        event_type="water_reading",
        status="ACTIVE",
    )

    with pytest.raises(MappingError, match="ambiguous") as exc:
        registry.select(
            twin_identity="twin:A",
            event_type="water_reading",
        )
    assert exc.value.code is MappingErrorCode.UNKNOWN_SCHEMA
    selected = registry.select(
        twin_identity="twin:A",
        event_type="water_reading",
        schema_id="schema-v2",
        schema_version="1.0",
    )
    assert selected.schema_id == "schema-v2"


def test_ensure_active_creates_pending_without_runtime_promotion(tmp_path):
    registry = ProfileRegistry(tmp_path)
    record = registry.ensure_active(
        measurement_profile("proposal", "proposal-schema"),
        twin_identity="twin:A",
        event_type="water_reading",
    )

    assert record.status == "PENDING"
    with pytest.raises(MappingError) as exc:
        registry.select(
            twin_identity="twin:A",
            event_type="water_reading",
            schema_id="proposal-schema",
            schema_version="1.0",
        )
    assert exc.value.code is MappingErrorCode.UNKNOWN_SCHEMA


def test_distinct_schema_ids_and_versions_remain_active_together(tmp_path):
    registry = ProfileRegistry(tmp_path)
    water_v1 = registry.register_profile(
        measurement_profile("water-v1", "water", "1.0"),
        twin_identity="twin:A",
        event_type="reading",
        status="ACTIVE",
    )
    temperature_v1 = registry.register_profile(
        measurement_profile("temperature-v1", "temperature", "1.0"),
        twin_identity="twin:A",
        event_type="reading",
        status="PENDING",
    )
    temperature_v2 = registry.register_profile(
        measurement_profile("temperature-v2", "temperature", "2.0"),
        twin_identity="twin:A",
        event_type="reading",
        status="PENDING",
    )

    registry.activate(temperature_v1.fingerprint)
    registry.activate(temperature_v2.fingerprint)

    assert registry.get(water_v1.fingerprint).status == "ACTIVE"
    assert registry.select(
        twin_identity="twin:A",
        event_type="reading",
        schema_id="water",
        schema_version="1.0",
    ).schema_id == "water"
    assert registry.select(
        twin_identity="twin:A",
        event_type="reading",
        schema_id="temperature",
        schema_version="1.0",
    ).version == "1.0"
    assert registry.select(
        twin_identity="twin:A",
        event_type="reading",
        schema_id="temperature",
        schema_version="2.0",
    ).version == "2.0"
