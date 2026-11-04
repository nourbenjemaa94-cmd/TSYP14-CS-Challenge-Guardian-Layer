"""Production mapping profile for signed Twin sensor envelopes."""

from .profile import MappingProfile, load_profile


def sensor_reading_profile() -> MappingProfile:
    """Return the validated profile used by the production ingestion route."""
    return load_profile(
        {
            "profile_id": "twin-canonical-v1",
            "schema_id": "twin-canonical-v1",
            "event_kind": "measurement",
            "metric_path": "$.payload.metric",
            "metric_map": {"waterLevel": "water_level"},
            "value_path": "$.payload.value",
            "unit_path": "$.payload.unit",
        }
    )


def sensor_reading_batch_profile() -> MappingProfile:
    """Profile for a signed envelope containing two or more sensor items."""
    return load_profile(
        {
            "profile_id": "twin-canonical-batch-v1",
            "schema_id": "twin-canonical-batch-v1",
            "batch_path": "$.payload.readings",
            "sensor_id_path": "@.sensor_id",
            "timestamp_path": "@.timestamp",
            "event_kind": "measurement",
            "metric_path": "@.metric",
            "metric_map": {"waterLevel": "water_level"},
            "value_path": "@.value",
            "unit_path": "@.unit",
        }
    )


def status_profile() -> MappingProfile:
    return load_profile(
        {
            "profile_id": "device-status-v1",
            "schema_id": "device-status-v1",
            "event_kind": "status",
            "status_path": "$.payload.status",
        }
    )


def discrete_event_profile() -> MappingProfile:
    return load_profile(
        {
            "profile_id": "discrete-event-v1",
            "schema_id": "discrete-event-v1",
            "event_kind": "discrete_event",
            "event_name_path": "$.payload.event_name",
        }
    )


def media_reference_profile() -> MappingProfile:
    return load_profile(
        {
            "profile_id": "media-reference-v1",
            "schema_id": "media-reference-v1",
            "event_kind": "media_reference",
            "media_type_path": "$.payload.media_type",
            "uri_path": "$.payload.uri",
        }
    )


def production_profiles() -> dict[str, MappingProfile]:
    """Validated profiles selected by the signed envelope's message type."""
    return {
        "sensor_reading": sensor_reading_profile(),
        "sensor_reading_batch": sensor_reading_batch_profile(),
        "device_status": status_profile(),
        "discrete_event": discrete_event_profile(),
        "media_reference": media_reference_profile(),
    }
