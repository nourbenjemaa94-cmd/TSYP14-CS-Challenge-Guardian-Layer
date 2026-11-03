"""Mapping profiles: how one partner payload shape becomes Guardian events.

A profile is data (JSON or YAML), validated strictly so that a wrong or
model-generated profile fails here, before it can touch a message. ``$``
paths read the accepted envelope, ``@`` paths one batch item. Identity and
time default to the envelope (``source.device_id``, ``timestamp``) unless the
profile says otherwise (handoff section 7).
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .errors import MappingError, MappingErrorCode
from .paths import split_path
from .unit_converter import normalize_unit

EventKind = Literal["measurement", "status", "discrete_event", "media_reference"]
TimestampFormat = Literal["iso", "unix_s", "unix_ms"]

ENVELOPE_SENSOR_ID_PATH = "$.source.device_id"
ENVELOPE_TIMESTAMP_PATH = "$.timestamp"

_METRIC_NAME = re.compile(r"[A-Za-z0-9_.:\-]{1,64}")

_PATH_FIELDS_BY_KIND: dict[str, tuple[str, ...]] = {
    "measurement": ("metric_path", "value_path", "unit_path"),
    "status": ("status_path",),
    "discrete_event": ("event_name_path", "detected_path", "confidence_path"),
    "media_reference": ("media_type_path", "uri_path"),
}
_MEASUREMENT_ONLY = ("metric_value", "unit_value")


class MappingProfile(BaseModel):
    """Reusable instructions for turning one external schema into Guardian events."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    schema_id: str = Field(min_length=1, max_length=128)
    version: str = "1.0"

    batch_path: str | None = None
    twin_id_path: str | None = None
    sensor_id_path: str = ENVELOPE_SENSOR_ID_PATH
    timestamp_path: str = ENVELOPE_TIMESTAMP_PATH
    timestamp_format: TimestampFormat = "iso"

    event_kind: EventKind

    # measurement: metric and unit come from a path OR a constant (handoff item 2).
    metric_path: str | None = None
    metric_value: str | None = None
    metric_map: dict[str, str] = Field(default_factory=dict)
    value_path: str | None = None
    unit_path: str | None = None
    unit_value: str | None = None

    status_path: str | None = None

    event_name_path: str | None = None
    detected_path: str | None = None
    confidence_path: str | None = None

    media_type_path: str | None = None
    uri_path: str | None = None

    @model_validator(mode="after")
    def validate_required_paths(self) -> MappingProfile:
        kind = self.event_kind
        if kind == "measurement":
            if (self.metric_path is None) == (self.metric_value is None):
                raise ValueError("measurement profiles need exactly one of metric_path or metric_value")
            if self.value_path is None:
                raise ValueError("measurement profiles need value_path")
            if (self.unit_path is None) == (self.unit_value is None):
                raise ValueError("measurement profiles need exactly one of unit_path or unit_value")
            if self.metric_map and self.metric_path is None:
                raise ValueError("metric_map is only used together with metric_path")
            if self.metric_value is not None and not _METRIC_NAME.fullmatch(self.metric_value):
                raise ValueError("metric_value must be 1-64 chars of letters, digits, _ . : -")
            for name, canonical in self.metric_map.items():
                if not _METRIC_NAME.fullmatch(name) or not _METRIC_NAME.fullmatch(canonical):
                    raise ValueError("metric_map entries must be 1-64 chars of letters, digits, _ . : -")
            if self.unit_value is not None:
                try:
                    normalize_unit(self.unit_value)
                except MappingError as exc:
                    raise ValueError(f"unit_value: {exc.detail}") from exc
        elif kind == "status":
            if not self.status_path:
                raise ValueError("status profiles need status_path")
        elif kind == "discrete_event":
            if not self.event_name_path:
                raise ValueError("discrete event profiles need event_name_path")
        elif kind == "media_reference":
            if not (self.media_type_path and self.uri_path):
                raise ValueError("media profiles need media_type_path and uri_path")

        for other_kind, fields in _PATH_FIELDS_BY_KIND.items():
            if other_kind == kind:
                continue
            for field_name in fields:
                if getattr(self, field_name) is not None:
                    raise ValueError(f"{field_name} is not used by event_kind {kind}")
        if kind != "measurement":
            for field_name in _MEASUREMENT_ONLY:
                if getattr(self, field_name) is not None:
                    raise ValueError(f"{field_name} is not used by event_kind {kind}")
            if self.metric_map:
                raise ValueError(f"metric_map is not used by event_kind {kind}")

        for name, path in self.paths().items():
            try:
                root, _ = split_path(path)
            except ValueError as exc:
                raise ValueError(f"{name}: {exc}") from exc
            if root == "@" and self.batch_path is None:
                raise ValueError(f"{name}: '@' paths need batch_path")
        if self.batch_path is not None and not self.batch_path.startswith("$"):
            raise ValueError("batch_path must start with '$'")
        return self

    def paths(self) -> dict[str, str]:
        """Every path field that is set, by field name."""
        names = ("batch_path", "twin_id_path", "sensor_id_path", "timestamp_path") + tuple(
            field for fields in _PATH_FIELDS_BY_KIND.values() for field in fields
        )
        return {name: getattr(self, name) for name in names if getattr(self, name) is not None}


def load_profile(data: dict[str, Any]) -> MappingProfile:
    """Validate profile data, turning pydantic errors into ``INVALID_PROFILE``."""
    try:
        return MappingProfile.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or 'profile'}: {error['msg']}"
            for error in exc.errors()
        )
        raise MappingError(MappingErrorCode.INVALID_PROFILE, problems) from exc
