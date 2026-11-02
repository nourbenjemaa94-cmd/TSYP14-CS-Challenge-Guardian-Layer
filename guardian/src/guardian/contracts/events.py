"""Canonical numeric sensor reading consumed by core.history.Reading.from_message.

The security envelope (schema_version/source/seq/signature/...) is a separate
contract already implemented by guardian.security.validation.Envelope.
"""
from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator

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
        return value.astimezone(timezone.utc)

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
