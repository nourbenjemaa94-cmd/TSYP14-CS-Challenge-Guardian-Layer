"""Size, JSON, and envelope checks.

Rejects oversized bodies, unsafe JSON, a wrong schema major version, and
envelopes that are missing required fields. Unknown fields are ignored.
Payload contents are not interpreted here.
"""

import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from guardian.security.errors import ReasonCode, SecurityRejection

_EVENT_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
_SCHEMA_VERSION = re.compile(r"^\d+\.\d+$")
_MESSAGE_TYPE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class Source(BaseModel):
    """Who claims to have sent the envelope, after the signature has been checked."""

    model_config = ConfigDict(extra="ignore")

    layer: str
    device_id: str | None = None

    @field_validator("layer")
    @classmethod
    def _layer(cls, value: object) -> str:
        if value not in {"twin", "brain", "guardian"}:
            raise ValueError("layer must be twin, brain, or guardian")
        return str(value)

    @field_validator("device_id")
    @classmethod
    def _device_id(cls, value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("device_id must be 1-128 characters from [A-Za-z0-9._:-]")
        return value


class Envelope(BaseModel):
    """Shared message envelope. Extra fields are ignored and never fatal."""

    model_config = ConfigDict(extra="ignore")

    schema_version: str
    event_id: str
    seq: int
    timestamp: str
    source: Source
    type: str
    payload: dict[str, Any]
    zone_id: str | None = None
    signature: str | None = None

    @field_validator("schema_version")
    @classmethod
    def _schema_version(cls, value: object) -> str:
        if not isinstance(value, str) or _SCHEMA_VERSION.fullmatch(value) is None:
            raise ValueError("schema_version must be MAJOR.MINOR")
        return value

    @field_validator("event_id")
    @classmethod
    def _event_id(cls, value: object) -> str:
        if not isinstance(value, str) or _EVENT_ID.fullmatch(value) is None:
            raise ValueError("event_id must be 1-128 characters from [A-Za-z0-9._:-]")
        return value

    @field_validator("seq", mode="before")
    @classmethod
    def _seq(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("seq must be an integer >= 0")
        return value

    @field_validator("timestamp")
    @classmethod
    def _timestamp(cls, value: object) -> str:
        if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
            raise ValueError("timestamp must be ISO-8601 UTC with millisecond precision")
        # Reject impossible calendar dates that still match the shape.
        from datetime import datetime

        try:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError as exc:
            raise ValueError("timestamp is not a real UTC time") from exc
        return value

    @field_validator("type")
    @classmethod
    def _type(cls, value: object) -> str:
        if not isinstance(value, str) or _MESSAGE_TYPE.fullmatch(value) is None:
            raise ValueError("type must be a lowercase message name")
        return value

    @field_validator("zone_id")
    @classmethod
    def _zone_id(cls, value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("zone_id must be 1-128 characters from [A-Za-z0-9._:-]")
        return value

    @field_validator("payload", mode="before")
    @classmethod
    def _payload(cls, value: object) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("payload must be an object")
        return value


def check_size(raw: bytes, max_bytes: int) -> None:
    """Refuse a body larger than the configured limit before it is parsed."""
    if len(raw) > max_bytes:
        raise SecurityRejection(ReasonCode.MESSAGE_TOO_LARGE)


def parse_json_object(raw: bytes) -> dict[str, Any]:
    """Parse a UTF-8 JSON object. Parser errors stay internal."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise SecurityRejection(ReasonCode.MALFORMED_JSON, detail="Body is not UTF-8.") from None
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        raise SecurityRejection(ReasonCode.MALFORMED_JSON, detail="JSON parse failed.") from None
    if not isinstance(value, dict):
        raise SecurityRejection(
            ReasonCode.SCHEMA_INVALID,
            fields=["body"],
            detail="JSON root must be an object.",
        )
    return value


def safe_event_id(body: dict[str, Any]) -> str | None:
    """Return ``event_id`` only when it is safe to echo to the sender."""
    event_id = body.get("event_id")
    if isinstance(event_id, str) and _EVENT_ID.fullmatch(event_id):
        return event_id
    return None


def claimed_source(body: dict[str, Any]) -> str | None:
    """A log-safe view of the claimed source. This is not an authenticated identity."""
    source = body.get("source")
    if not isinstance(source, dict):
        return None
    layer = source.get("layer")
    if not isinstance(layer, str) or re.fullmatch(r"[A-Za-z0-9._:-]{1,32}", layer) is None:
        return None
    device_id = source.get("device_id")
    if device_id is None:
        return layer
    if isinstance(device_id, str) and _IDENTIFIER.fullmatch(device_id):
        return f"{layer}:{device_id}"
    return layer


def validate_envelope(
    data: dict[str, Any],
    *,
    schema_major: int,
    allowed_types: tuple[str, ...] = (),
) -> Envelope:
    """Validate the canonical envelope. A different schema major is refused."""
    event_id = safe_event_id(data)
    try:
        envelope = Envelope.model_validate(data)
    except ValidationError as exc:
        raise SecurityRejection(
            ReasonCode.SCHEMA_INVALID,
            event_id=event_id,
            fields=_field_names(exc),
            detail="Envelope validation failed.",
        ) from None

    problems: list[str] = []
    major_text, _minor = envelope.schema_version.split(".", 1)
    if int(major_text) != schema_major:
        problems.append("schema_version")
    if allowed_types and envelope.type not in allowed_types:
        problems.append("type")
    if problems:
        raise SecurityRejection(
            ReasonCode.SCHEMA_INVALID,
            event_id=envelope.event_id,
            fields=problems,
            detail="Envelope was structurally valid but failed a schema rule.",
        )
    return envelope


def _field_names(exc: ValidationError) -> list[str]:
    names: list[str] = []
    for error in exc.errors():
        location = error.get("loc") or ()
        if not location:
            names.append("body")
            continue
        names.append(".".join(str(part) for part in location))
    return sorted(set(names)) or ["body"]
