"""Handoff section 10: the diagram example, the variant set, batches, timestamps, errors."""

from datetime import UTC, datetime, timedelta

import pytest

from guardian.adapters.contract import BATCH_ID_SEPARATOR, MappingError, MappingErrorCode, load_profile
from guardian.contracts.events import SensorEvent

from .conftest import FIXED, envelope, measurement_profile

DIAGRAM_PROFILE = measurement_profile(
    metric_value="water_level", value_path="$.payload.levelOfWater", unit_path="$.payload.unit"
)
DIAGRAM_MESSAGE = envelope({"sensor_id": "S01", "levelOfWater": 1.8, "unit": "m"})


def test_diagram_example_maps_to_canonical_reading(mapper):
    (event,) = mapper.map_message(DIAGRAM_MESSAGE, DIAGRAM_PROFILE, "rest")
    assert event.event_id == "EVT-1"
    assert event.kind == "measurement"
    assert event.sensor_id == "S01"  # from the envelope source, not the payload
    assert event.occurred_at == FIXED
    assert event.payload == {"metric": "water_level", "value": 180.0, "unit": "cm"}
    assert event.provenance.source_adapter == "rest"
    assert event.provenance.mapping_profile_id == "test-v1"
    assert event.provenance.profile_status == "ACTIVE"
    assert event.twin_id is None


def test_probation_status_is_copied_onto_the_event(mapper):
    (event,) = mapper.map_message(DIAGRAM_MESSAGE, DIAGRAM_PROFILE, "rest", profile_status="PROBATION")
    assert event.provenance.profile_status == "PROBATION"


def test_measurement_event_feeds_the_core(mapper):
    (event,) = mapper.map_message(DIAGRAM_MESSAGE, DIAGRAM_PROFILE)
    sensor_event = event.to_sensor_event()
    assert isinstance(sensor_event, SensorEvent)
    assert sensor_event.to_core_dict() == {
        "event_id": "EVT-1", "sensor_id": "S01", "metric": "water_level",
        "value": 180.0, "unit": "cm", "timestamp": "2026-11-03T10:00:00Z",
    }


def test_mapping_is_deterministic(mapper):
    first = mapper.map_message(DIAGRAM_MESSAGE, DIAGRAM_PROFILE)
    second = mapper.map_message(DIAGRAM_MESSAGE, DIAGRAM_PROFILE)
    assert first == second


UNIX_S = int(FIXED.timestamp())
UNIX_MS = UNIX_S * 1000

# Variant test set (handoff section 10). Every variant must map to the same canonical reading.
VARIANTS = {
    "snake_case_cm": (
        {"water_level_cm": 180, "unit": "cm"},
        {"metric_value": "water_level", "value_path": "$.payload.water_level_cm", "unit_path": "$.payload.unit"},
    ),
    "camelCase_m": (
        {"levelOfWater": 1.8, "unit": "m"},
        {"metric_value": "water_level", "value_path": "$.payload.levelOfWater", "unit_path": "$.payload.unit"},
    ),
    "mm_with_unit_constant": (
        {"level_mm": 1800},
        {"metric_value": "water_level", "value_path": "$.payload.level_mm", "unit_value": "mm"},
    ),
    "renamed_metric_via_metric_map": (
        {"metric": "waterLevel", "value": 180, "unit": "cm"},
        {"metric_path": "$.payload.metric", "metric_map": {"waterLevel": "water_level"},
         "value_path": "$.payload.value", "unit_path": "$.payload.unit"},
    ),
    "canonical_payload_as_the_mock_twin_sends_it": (
        {"metric": "water_level", "value": 180, "unit": "cm"},
        {"metric_path": "$.payload.metric", "value_path": "$.payload.value", "unit_path": "$.payload.unit"},
    ),
    "nested_reading_object": (
        {"reading": {"depth": {"val": 1.8, "uom": "meters"}}},
        {"metric_value": "water_level", "value_path": "$.payload.reading.depth.val",
         "unit_path": "$.payload.reading.depth.uom"},
    ),
    "occurred_at_iso_with_offset_in_payload": (
        {"levelOfWater": 1.8, "unit": "m", "measuredAt": "2026-11-03T11:00:00+01:00"},
        {"metric_value": "water_level", "value_path": "$.payload.levelOfWater", "unit_path": "$.payload.unit",
         "timestamp_path": "$.payload.measuredAt"},
    ),
    "occurred_at_unix_seconds": (
        {"levelOfWater": 1.8, "unit": "m", "ts": UNIX_S},
        {"metric_value": "water_level", "value_path": "$.payload.levelOfWater", "unit_path": "$.payload.unit",
         "timestamp_path": "$.payload.ts", "timestamp_format": "unix_s"},
    ),
    "occurred_at_unix_milliseconds": (
        {"levelOfWater": 1.8, "unit": "m", "ts": UNIX_MS},
        {"metric_value": "water_level", "value_path": "$.payload.levelOfWater", "unit_path": "$.payload.unit",
         "timestamp_path": "$.payload.ts", "timestamp_format": "unix_ms"},
    ),
    "sensor_id_from_payload_when_profile_says_so": (
        {"gauge": "S01", "levelOfWater": 1.8, "unit": "m"},
        {"metric_value": "water_level", "value_path": "$.payload.levelOfWater", "unit_path": "$.payload.unit",
         "sensor_id_path": "$.payload.gauge"},
    ),
}


@pytest.mark.parametrize("name", sorted(VARIANTS))
def test_variants_map_to_the_same_canonical_reading(mapper, name):
    payload, profile_fields = VARIANTS[name]
    (event,) = mapper.map_message(envelope(payload), measurement_profile(**profile_fields))
    assert event.sensor_id == "S01"
    assert event.occurred_at == FIXED
    assert event.payload["metric"] == "water_level"
    assert event.payload["unit"] == "cm"
    assert event.payload["value"] == pytest.approx(180.0)


def test_batch_produces_one_event_per_item_with_derived_ids(mapper):
    message = envelope({"readings": [{"id": "S01", "v": 1.8, "u": "m"}, {"id": "S02", "v": 0.4, "u": "m"}]})
    profile = measurement_profile(
        batch_path="$.payload.readings", sensor_id_path="@.id",
        metric_value="water_level", value_path="@.v", unit_path="@.u",
    )
    events = mapper.map_message(message, profile)
    assert [e.event_id for e in events] == [f"EVT-1{BATCH_ID_SEPARATOR}0", f"EVT-1{BATCH_ID_SEPARATOR}1"]
    assert [e.sensor_id for e in events] == ["S01", "S02"]
    assert [e.payload["value"] for e in events] == [180.0, 40.0]
    assert all(e.occurred_at == FIXED for e in events)  # time still from the envelope
    assert all(e.to_sensor_event() for e in events)  # derived ids pass the SensorEvent pattern


def test_twin_id_is_optional_and_kept_in_the_event(mapper):
    message = envelope({"twin": "port-twin", "levelOfWater": 1.8, "unit": "m"})
    profile = measurement_profile(
        twin_id_path="$.payload.twin", metric_value="water_level",
        value_path="$.payload.levelOfWater", unit_path="$.payload.unit",
    )
    (event,) = mapper.map_message(message, profile)
    assert event.twin_id == "port-twin"


def _expect(mapper, message, profile, code, path=None):
    with pytest.raises(MappingError) as info:
        mapper.map_message(message, profile)
    assert info.value.code is code
    assert info.value.event_id == "EVT-1"
    if path is not None:
        assert info.value.path == path
    return info.value


def test_missing_path_is_reported_by_path_not_value(mapper):
    err = _expect(mapper, envelope({"unit": "m"}), DIAGRAM_PROFILE, MappingErrorCode.PATH_NOT_FOUND,
                  "$.payload.levelOfWater")
    assert err.to_public_dict() == {
        "error": "PATH_NOT_FOUND", "message": "A field required by the mapping profile is missing.",
        "event_id": "EVT-1", "path": "$.payload.levelOfWater",
    }


def test_unknown_unit(mapper):
    _expect(mapper, envelope({"levelOfWater": 1.8, "unit": "furlong"}), DIAGRAM_PROFILE,
            MappingErrorCode.UNSUPPORTED_UNIT, "$.payload.unit")


def test_unit_of_wrong_dimension(mapper):
    _expect(mapper, envelope({"levelOfWater": 1.8, "unit": "kPa"}), DIAGRAM_PROFILE,
            MappingErrorCode.UNSUPPORTED_UNIT)


@pytest.mark.parametrize("bad", ["1.8", True, None, float("nan"), [1.8]])
def test_non_numeric_value(mapper, bad):
    err = _expect(mapper, envelope({"levelOfWater": bad, "unit": "m"}), DIAGRAM_PROFILE,
                  MappingErrorCode.INVALID_VALUE, "$.payload.levelOfWater")
    assert "1.8" not in str(err)  # detail names the path, never the value


def test_timestamp_without_timezone(mapper):
    message = envelope({"levelOfWater": 1.8, "unit": "m"}, timestamp="2026-11-03T10:00:00")
    _expect(mapper, message, DIAGRAM_PROFILE, MappingErrorCode.INVALID_TIMESTAMP, "$.timestamp")


@pytest.mark.parametrize("bad", ["yesterday", True, None, float("inf"), -5, UNIX_MS])
def test_bad_unix_seconds(mapper, bad):
    profile = measurement_profile(
        metric_value="water_level", value_path="$.payload.v", unit_value="cm",
        timestamp_path="$.payload.ts", timestamp_format="unix_s",
    )
    _expect(mapper, envelope({"v": 180, "ts": bad}), profile, MappingErrorCode.INVALID_TIMESTAMP, "$.payload.ts")


def test_missing_event_id(mapper):
    message = envelope({"levelOfWater": 1.8, "unit": "m"})
    del message["event_id"]
    with pytest.raises(MappingError) as info:
        mapper.map_message(message, DIAGRAM_PROFILE)
    assert info.value.code is MappingErrorCode.PATH_NOT_FOUND
    assert info.value.path == "$.event_id"


def test_batch_path_must_point_to_a_list(mapper):
    profile = measurement_profile(batch_path="$.payload.readings", metric_value="water_level",
                                  value_path="@.v", unit_value="cm")
    _expect(mapper, envelope({"readings": {"v": 1}}), profile, MappingErrorCode.INVALID_VALUE, "$.payload.readings")


def test_bad_sensor_id(mapper):
    _expect(mapper, envelope({"levelOfWater": 1.8, "unit": "m"}, source={"layer": "twin", "device_id": "S 01"}),
            DIAGRAM_PROFILE, MappingErrorCode.INVALID_VALUE, "$.source.device_id")


def test_status_event(mapper):
    profile = load_profile({"profile_id": "st", "schema_id": "st", "event_kind": "status",
                            "status_path": "$.payload.state"})
    (event,) = mapper.map_message(envelope({"state": "ONLINE"}, type="device_status"), profile)
    assert event.kind == "status"
    assert event.payload == {"status": "ONLINE"}
    with pytest.raises(ValueError):
        event.to_sensor_event()


def test_discrete_event_bounds(mapper):
    profile = load_profile({"profile_id": "de", "schema_id": "de", "event_kind": "discrete_event",
                            "event_name_path": "$.payload.name", "detected_path": "$.payload.hit",
                            "confidence_path": "$.payload.conf"})
    (event,) = mapper.map_message(envelope({"name": "flood", "hit": True, "conf": 0.9}), profile)
    assert event.payload == {"event_name": "flood", "detected": True, "confidence": 0.9}
    _expect(mapper, envelope({"name": "flood", "hit": True, "conf": 1.5}), profile,
            MappingErrorCode.INVALID_VALUE, "$.payload.conf")
    _expect(mapper, envelope({"name": "flood", "hit": "yes", "conf": 0.5}), profile,
            MappingErrorCode.INVALID_VALUE, "$.payload.hit")


def test_media_reference_is_recorded_not_fetched(mapper):
    profile = load_profile({"profile_id": "mr", "schema_id": "mr", "event_kind": "media_reference",
                            "media_type_path": "$.payload.mime", "uri_path": "$.payload.url"})
    (event,) = mapper.map_message(envelope({"mime": "image/jpeg", "url": "https://cam.example/1.jpg"}), profile)
    assert event.payload == {"media_type": "image/jpeg", "uri": "https://cam.example/1.jpg"}
    _expect(mapper, envelope({"mime": "image/jpeg", "url": "file:///etc/passwd"}), profile,
            MappingErrorCode.INVALID_VALUE, "$.payload.url")


def test_occurred_at_is_normalised_to_utc(mapper):
    local = (FIXED + timedelta(hours=1)).replace(tzinfo=None).isoformat() + "+01:00"
    (event,) = mapper.map_message(envelope({"levelOfWater": 1.8, "unit": "m"}, timestamp=local), DIAGRAM_PROFILE)
    assert event.occurred_at == FIXED
    assert event.occurred_at.tzinfo is UTC or event.occurred_at.utcoffset() == timedelta(0)
    assert isinstance(event.occurred_at, datetime)
