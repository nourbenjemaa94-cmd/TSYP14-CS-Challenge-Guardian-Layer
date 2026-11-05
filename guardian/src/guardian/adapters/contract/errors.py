"""Stable error codes for the contract adapter (handoff section 6, item 15).

A ``MappingError`` carries a code that partners and operators can act on, a
public message that is safe to return, and a ``detail`` for logs. ``detail``
may name profile paths and field names, never payload values or secrets.
"""

from __future__ import annotations

from enum import StrEnum


class MappingErrorCode(StrEnum):
    UNKNOWN_SCHEMA = "UNKNOWN_SCHEMA"
    ONBOARDING_PENDING = "ONBOARDING_PENDING"
    UNMAPPABLE_SCHEMA = "UNMAPPABLE_SCHEMA"
    PROFILE_NOT_ACTIVE = "PROFILE_NOT_ACTIVE"
    INVALID_PROFILE = "INVALID_PROFILE"
    PATH_NOT_FOUND = "PATH_NOT_FOUND"
    INVALID_VALUE = "INVALID_VALUE"
    UNSUPPORTED_UNIT = "UNSUPPORTED_UNIT"
    INVALID_TIMESTAMP = "INVALID_TIMESTAMP"


PUBLIC_MESSAGES: dict[MappingErrorCode, str] = {
    MappingErrorCode.UNKNOWN_SCHEMA: "No mapping profile is known for this message format.",
    MappingErrorCode.ONBOARDING_PENDING: "This message format is being onboarded.",
    MappingErrorCode.UNMAPPABLE_SCHEMA: "This message format could not be mapped automatically.",
    MappingErrorCode.PROFILE_NOT_ACTIVE: "The mapping profile for this message format is not active.",
    MappingErrorCode.INVALID_PROFILE: "The mapping profile is not valid.",
    MappingErrorCode.PATH_NOT_FOUND: "A field required by the mapping profile is missing.",
    MappingErrorCode.INVALID_VALUE: "A mapped field has the wrong type or an invalid value.",
    MappingErrorCode.UNSUPPORTED_UNIT: "The measurement unit is not supported.",
    MappingErrorCode.INVALID_TIMESTAMP: "The timestamp is missing, malformed or has no timezone.",
}

HTTP_STATUS: dict[MappingErrorCode, int] = {
    MappingErrorCode.UNKNOWN_SCHEMA: 422,
    MappingErrorCode.ONBOARDING_PENDING: 202,
    MappingErrorCode.UNMAPPABLE_SCHEMA: 422,
    MappingErrorCode.PROFILE_NOT_ACTIVE: 503,
    MappingErrorCode.INVALID_PROFILE: 500,
    MappingErrorCode.PATH_NOT_FOUND: 422,
    MappingErrorCode.INVALID_VALUE: 422,
    MappingErrorCode.UNSUPPORTED_UNIT: 422,
    MappingErrorCode.INVALID_TIMESTAMP: 422,
}


class MappingError(Exception):
    """Raised when a message cannot be turned into Guardian events."""

    def __init__(
        self,
        code: MappingErrorCode,
        detail: str | None = None,
        *,
        path: str | None = None,
        event_id: str | None = None,
        fingerprint: str | None = None,
    ) -> None:
        self.code = code
        self.path = path
        self.event_id = event_id
        self.fingerprint = fingerprint
        self.public_message = PUBLIC_MESSAGES[code]
        self.http_status = HTTP_STATUS[code]
        self.detail = detail or self.public_message
        super().__init__(f"{code.value}: {self.detail}")

    def to_public_dict(self) -> dict[str, object]:
        """Shape shared with ``SecurityRejection.to_public_dict``; safe for partners."""
        if self.code is MappingErrorCode.ONBOARDING_PENDING:
            body: dict[str, object] = {
                "status": "ONBOARDING_PENDING",
                "error": self.code.value,
                "message": self.public_message,
            }
            if self.fingerprint is not None:
                body["fingerprint"] = self.fingerprint
            if self.event_id is not None:
                body["event_id"] = self.event_id
            return body
        body = {"error": self.code.value, "message": self.public_message}
        if self.event_id is not None:
            body["event_id"] = self.event_id
        if self.path is not None:
            body["path"] = self.path
        return body
