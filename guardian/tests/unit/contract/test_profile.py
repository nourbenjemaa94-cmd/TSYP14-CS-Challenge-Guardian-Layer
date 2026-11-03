"""Handoff section 6 item 2 (constants) and item 15 (MappingError) at profile level."""

import pytest

from guardian.adapters.contract import MappingError, MappingErrorCode, load_profile


def _bad(data: dict, fragment: str) -> None:
    with pytest.raises(MappingError) as info:
        load_profile(data)
    assert info.value.code is MappingErrorCode.INVALID_PROFILE
    assert fragment in info.value.detail


def test_diagram_profile_with_constant_metric_loads():
    profile = load_profile({
        "profile_id": "twin-diagram-v1", "schema_id": "twin-diagram", "event_kind": "measurement",
        "metric_value": "water_level", "value_path": "$.payload.levelOfWater", "unit_path": "$.payload.unit",
    })
    assert profile.sensor_id_path == "$.source.device_id"
    assert profile.timestamp_path == "$.timestamp"
    assert profile.timestamp_format == "iso"


def test_team_pdf_batch_example_loads():
    profile = load_profile({
        "profile_id": "twin-a-v1", "schema_id": "twin-a-v1", "version": "1.0",
        "batch_path": "$.payload.sensors", "twin_id_path": "$.payload.twin_id",
        "sensor_id_path": "@.id", "timestamp_path": "@.timestamp", "event_kind": "measurement",
        "metric_path": "@.type", "value_path": "@.value", "unit_path": "@.unit",
    })
    assert set(profile.paths()) == {
        "batch_path", "twin_id_path", "sensor_id_path", "timestamp_path", "metric_path", "value_path", "unit_path",
    }


BASE = {"profile_id": "p", "schema_id": "s", "event_kind": "measurement",
        "metric_value": "water_level", "value_path": "$.payload.v", "unit_value": "cm"}


def test_metric_path_and_metric_value_are_exclusive():
    _bad({**BASE, "metric_path": "$.payload.m"}, "exactly one of metric_path or metric_value")


def test_unit_path_and_unit_value_are_exclusive():
    _bad({**BASE, "unit_path": "$.payload.u"}, "exactly one of unit_path or unit_value")


def test_value_path_required():
    data = dict(BASE)
    del data["value_path"]
    _bad(data, "value_path")


def test_metric_map_needs_metric_path():
    _bad({**BASE, "metric_map": {"lvl": "water_level"}}, "metric_map")


def test_unit_value_must_be_known():
    _bad({**BASE, "unit_value": "furlong"}, "unit_value")


def test_field_of_another_kind_refused():
    _bad({**BASE, "uri_path": "$.payload.uri"}, "uri_path is not used by event_kind measurement")


def test_constants_refused_outside_measurement():
    _bad({"profile_id": "p", "schema_id": "s", "event_kind": "status", "status_path": "$.payload.s",
          "unit_value": "cm"}, "unit_value is not used")


def test_unknown_key_refused():
    _bad({**BASE, "canonical_unit": "cm"}, "canonical_unit")


def test_bad_path_syntax_refused():
    _bad({**BASE, "value_path": "payload.v"}, "must start with")


def test_item_path_needs_batch_path():
    _bad({**BASE, "value_path": "@.v"}, "'@' paths need batch_path")


def test_bad_timestamp_format_refused():
    _bad({**BASE, "timestamp_format": "epoch"}, "timestamp_format")


def test_public_dict_hides_detail():
    with pytest.raises(MappingError) as info:
        load_profile({**BASE, "canonical_unit": "cm"})
    public = info.value.to_public_dict()
    assert public == {"error": "INVALID_PROFILE", "message": "The mapping profile is not valid."}
