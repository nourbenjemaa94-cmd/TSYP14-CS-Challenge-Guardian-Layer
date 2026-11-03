"""Deterministic payload-to-event mapping.

Runs after the security gate has accepted the envelope (handoff section 7):
``$`` is the accepted envelope, ``@`` one item of a batch. The mapper never
changes ``event_id``; batch items get ``<event_id>:<index>`` so the timeline
can trace them. No network, no model call, no clock: the same message and
profile always give the same events.
"""

from __future__ import annotations

import math
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from guardian.contracts.events import EventProvenance, GuardianEvent

from .errors import MappingError, MappingErrorCode
from .paths import resolve
from .profile import MappingProfile
from .unit_converter import UnitConverter

# '#' (handoff section 7) is rejected by the id patterns in contracts.events,
# core.history and security.validation; ':' is allowed by all three.
BATCH_ID_SEPARATOR = ":"

_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:\-]{1,64}")
_MEDIA_TYPE = re.compile(r"[a-z]+/[a-z0-9.+\-]{1,64}")
_URI_SCHEMES = ("https://", "http://", "rtsp://", "s3://")
_MAX_URI_LENGTH = 2048
_MAX_UNIX_SECONDS = 1e11  # beyond year 5000: almost certainly milliseconds mislabelled


def parse_timestamp(value: Any, timestamp_format: str = "iso") -> datetime:
    """Parse a partner timestamp into an aware UTC datetime (handoff item 12)."""
    if timestamp_format == "iso":
        if isinstance(value, datetime):
            stamp = value
        elif isinstance(value, str):
            text = value.strip()
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            try:
                stamp = datetime.fromisoformat(text)
            except ValueError as exc:
                raise MappingError(MappingErrorCode.INVALID_TIMESTAMP, "not an ISO-8601 timestamp") from exc
        else:
            raise MappingError(MappingErrorCode.INVALID_TIMESTAMP, "timestamp must be an ISO-8601 string")
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise MappingError(MappingErrorCode.INVALID_TIMESTAMP, "timestamp has no timezone")
        return stamp.astimezone(UTC)

    if timestamp_format in ("unix_s", "unix_ms"):
        number = value
        if isinstance(number, str):
            try:
                number = float(number.strip())
            except ValueError as exc:
                raise MappingError(MappingErrorCode.INVALID_TIMESTAMP, "unix timestamp is not numeric") from exc
        if isinstance(number, bool) or not isinstance(number, (int, float)) or not math.isfinite(number):
            raise MappingError(MappingErrorCode.INVALID_TIMESTAMP, "unix timestamp must be a finite number")
        seconds = float(number) / (1000.0 if timestamp_format == "unix_ms" else 1.0)
        if not 0 < seconds < _MAX_UNIX_SECONDS:
            raise MappingError(
                MappingErrorCode.INVALID_TIMESTAMP, f"unix timestamp out of range for {timestamp_format}"
            )
        return datetime.fromtimestamp(seconds, tz=UTC)

    raise MappingError(MappingErrorCode.INVALID_PROFILE, f"unknown timestamp_format {timestamp_format!r}")


def _finite_number(value: Any, path: str | None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise MappingError(MappingErrorCode.INVALID_VALUE, "value must be a finite number", path=path)
    return float(value)


def _identifier(value: Any, path: str | None, what: str) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise MappingError(
            MappingErrorCode.INVALID_VALUE, f"{what} must be 1-64 chars of letters, digits, _ . : -", path=path
        )
    return value


class GenericMapper:
    """Converts one accepted envelope into one or more ``GuardianEvent`` objects."""

    def __init__(self, unit_converter: UnitConverter | None = None) -> None:
        self.unit_converter = unit_converter or UnitConverter()

    def map_message(
        self,
        message: dict[str, Any],
        profile: MappingProfile,
        source_adapter: str = "unknown",
    ) -> list[GuardianEvent]:
        if not isinstance(message, dict):
            raise MappingError(MappingErrorCode.INVALID_VALUE, "message must be a JSON object")
        event_id = message.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            raise MappingError(MappingErrorCode.PATH_NOT_FOUND, "envelope has no event_id", path="$.event_id")

        if profile.batch_path:
            items = resolve(profile.batch_path, root=message, item=message)
            if not isinstance(items, list):
                raise MappingError(
                    MappingErrorCode.INVALID_VALUE, "batch_path must point to a list",
                    path=profile.batch_path, event_id=event_id,
                )
            ids = [f"{event_id}{BATCH_ID_SEPARATOR}{index}" for index in range(len(items))]
        else:
            items, ids = [message], [event_id]

        events: list[GuardianEvent] = []
        for item, item_id in zip(items, ids, strict=True):
            if not isinstance(item, dict):
                raise MappingError(
                    MappingErrorCode.INVALID_VALUE, "each batch item must be an object",
                    path=profile.batch_path, event_id=event_id,
                )
            try:
                events.append(self._map_one(message, item, profile, source_adapter, item_id))
            except MappingError as exc:
                if exc.event_id is None:
                    exc.event_id = item_id
                raise
        return events

    def _map_one(
        self,
        root: dict[str, Any],
        item: dict[str, Any],
        profile: MappingProfile,
        source_adapter: str,
        event_id: str,
    ) -> GuardianEvent:
        def get(path: str) -> Any:
            return resolve(path, root=root, item=item)

        sensor_id = _identifier(get(profile.sensor_id_path), profile.sensor_id_path, "sensor_id")
        twin_id = None
        if profile.twin_id_path:
            twin_id = _identifier(get(profile.twin_id_path), profile.twin_id_path, "twin_id")
        try:
            occurred_at = parse_timestamp(get(profile.timestamp_path), profile.timestamp_format)
        except MappingError as exc:
            exc.path = exc.path or profile.timestamp_path
            raise

        kind = profile.event_kind
        if kind == "measurement":
            payload = self._measurement(profile, get)
        elif kind == "status":
            payload = {"status": _identifier(get(profile.status_path), profile.status_path, "status")}
        elif kind == "discrete_event":
            payload = self._discrete_event(profile, get)
        elif kind == "media_reference":
            payload = self._media_reference(profile, get)
        else:  # pragma: no cover - the profile validator refuses other kinds
            raise MappingError(MappingErrorCode.INVALID_PROFILE, f"unsupported event kind {kind!r}")

        try:
            return GuardianEvent(
                event_id=event_id,
                kind=kind,
                sensor_id=sensor_id,
                occurred_at=occurred_at,
                payload=payload,
                twin_id=twin_id,
                provenance=EventProvenance(
                    source_adapter=source_adapter,
                    source_schema=profile.schema_id,
                    mapping_profile_id=profile.profile_id,
                    profile_version=profile.version,
                ),
            )
        except ValidationError as exc:
            fields = ", ".join(".".join(str(p) for p in e["loc"]) for e in exc.errors())
            raise MappingError(MappingErrorCode.INVALID_VALUE, f"event rejected by contract: {fields}") from exc

    def _measurement(self, profile: MappingProfile, get: Any) -> dict[str, Any]:
        if profile.metric_value is not None:
            metric = profile.metric_value
        else:
            raw_metric = _identifier(get(profile.metric_path), profile.metric_path, "metric")
            metric = profile.metric_map.get(raw_metric, raw_metric)
        value = _finite_number(get(profile.value_path), profile.value_path)
        unit = profile.unit_value if profile.unit_value is not None else get(profile.unit_path)
        try:
            value, unit = self.unit_converter.to_canonical(metric, value, unit)
        except MappingError as exc:
            exc.path = exc.path or profile.unit_path or profile.value_path
            raise
        return {"metric": metric, "value": value, "unit": unit}

    @staticmethod
    def _discrete_event(profile: MappingProfile, get: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "event_name": _identifier(get(profile.event_name_path), profile.event_name_path, "event_name")
        }
        if profile.detected_path:
            detected = get(profile.detected_path)
            if not isinstance(detected, bool):
                raise MappingError(MappingErrorCode.INVALID_VALUE, "detected must be a boolean", path=profile.detected_path)
            payload["detected"] = detected
        if profile.confidence_path:
            confidence = _finite_number(get(profile.confidence_path), profile.confidence_path)
            if not 0.0 <= confidence <= 1.0:
                raise MappingError(MappingErrorCode.INVALID_VALUE, "confidence must be within 0..1", path=profile.confidence_path)
            payload["confidence"] = confidence
        return payload

    @staticmethod
    def _media_reference(profile: MappingProfile, get: Any) -> dict[str, Any]:
        # Guardian records the reference only. It never fetches the URI (handoff item 14).
        media_type = get(profile.media_type_path)
        if not isinstance(media_type, str) or not _MEDIA_TYPE.fullmatch(media_type):
            raise MappingError(MappingErrorCode.INVALID_VALUE, "media_type must look like image/jpeg", path=profile.media_type_path)
        uri = get(profile.uri_path)
        if not isinstance(uri, str) or len(uri) > _MAX_URI_LENGTH or not uri.startswith(_URI_SCHEMES):
            raise MappingError(MappingErrorCode.INVALID_VALUE, "uri must be an http(s), rtsp or s3 URI", path=profile.uri_path)
        return {"media_type": media_type, "uri": uri}
