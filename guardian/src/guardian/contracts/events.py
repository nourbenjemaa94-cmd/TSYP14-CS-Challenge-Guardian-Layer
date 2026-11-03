"""Canonical numeric sensor reading consumed by core.history.Reading.from_message.

The security envelope (schema_version/source/seq/signature/...) is a separate
contract already implemented by guardian.security.validation.Envelope.
"""
from __future__ import annotations

import math
import re
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_ID = re.compile(r"[A-Za-z0-9_.:\-]{1,64}")


class SensorEvent(BaseModel):
    """Version-1 numeric reading. Do not use for camera/video/status events."""

    model_config = ConfigDict(extra="forbid", strict=True)

    event_id: str
    sensor_id: str
    metric: str
    value: float
    unit: str
    timestamp: datetime

    @field_validator("event_id")
    @classmethod
    def valid_event_id(cls, value: str) -> str:
        if not 1 <= len(value) <= 128 or not re.fullmatch(r"[A-Za-z0-9._:\-]+", value):
            raise ValueError("event_id must contain 1-128 safe characters")
        return value

    @field_validator("sensor_id", "metric")
    @classmethod
    def valid_identifier(cls, value: str) -> str:
        if not _ID.fullmatch(value):
            raise ValueError("invalid sensor_id/metric identifier")
        return value

    @field_validator("value", mode="before")
    @classmethod
    def valid_number(cls, value: Any) -> float:
        if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value):
            raise ValueError("value must be a finite numeric measurement")
        return float(value)

    @field_validator("unit")
    @classmethod
    def valid_unit(cls, value: str) -> str:
        if len(value) > 16:
            raise ValueError("unit must have at most 16 characters")
        return value

    @field_validator("timestamp")
    @classmethod
    def valid_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include timezone")
        return value.astimezone(UTC)

    def to_core_dict(self) -> dict[str, Any]:
        """Exact keys expected by existing core.history.Reading.from_message."""
        return {
            "event_id": self.event_id,
            "sensor_id": self.sensor_id,
            "metric": self.metric,
            "value": self.value,
            "unit": self.unit,
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
        }


# --- Contract-adapter output (handoff section 6; Members 1, 2, 6) ----------------
# TODO(guardian-integration): GuardianEvent/EventProvenance are new. SensorEvent is
# unchanged; the core keeps consuming SensorEvent.to_core_dict().

EventKind = Literal["measurement", "status", "discrete_event", "media_reference"]


class EventProvenance(BaseModel):
    """Where a GuardianEvent came from: adapter, partner schema and mapping profile."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_adapter: str
    source_schema: str
    mapping_profile_id: str
    profile_version: str = "1.0"
    # profile_status (PROBATION/ACTIVE) is added with the probation gate (handoff 8.4).


class GuardianEvent(BaseModel):
    """One canonical event mapped from a partner payload.

    ``payload`` depends on ``kind``. Only ``measurement`` events become a
    :class:`SensorEvent` for the numeric core. Batch items carry the envelope
    event_id with a ``:<index>`` suffix, which the id patterns below allow.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str
    kind: EventKind
    sensor_id: str
    occurred_at: datetime
    payload: dict[str, Any] = Field(default_factory=dict)
    provenance: EventProvenance
    twin_id: str | None = None

    @field_validator("event_id")
    @classmethod
    def valid_event_id(cls, value: str) -> str:
        if not 1 <= len(value) <= 128 or not re.fullmatch(r"[A-Za-z0-9._:\-]+", value):
            raise ValueError("event_id must contain 1-128 safe characters")
        return value

    @field_validator("sensor_id")
    @classmethod
    def valid_sensor_id(cls, value: str) -> str:
        if not _ID.fullmatch(value):
            raise ValueError("invalid sensor_id identifier")
        return value

    @field_validator("occurred_at")
    @classmethod
    def valid_occurred_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include timezone")
        return value.astimezone(UTC)

    def to_sensor_event(self) -> SensorEvent:
        """The numeric reading for the core. Only measurement events have one."""
        if self.kind != "measurement":
            raise ValueError(f"{self.kind} events carry no numeric reading")
        return SensorEvent(
            event_id=self.event_id,
            sensor_id=self.sensor_id,
            metric=self.payload["metric"],
            value=self.payload["value"],
            unit=self.payload["unit"],
            timestamp=self.occurred_at,
        )
