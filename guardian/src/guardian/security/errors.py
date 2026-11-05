"""Stable rejection reasons for Guardian's front door.

A partner only ever sees a reason code, a fixed public sentence, and an HTTP
status. Internal detail stays on the exception for logs and must not include
keys, signatures, or payload values.
"""

from enum import StrEnum


class ReasonCode(StrEnum):
    """Why a message was refused. Values are part of the public error contract."""

    MESSAGE_TOO_LARGE = "MESSAGE_TOO_LARGE"
    MALFORMED_JSON = "MALFORMED_JSON"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    SIGNATURE_MISSING = "SIGNATURE_MISSING"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    UNKNOWN_SENDER = "UNKNOWN_SENDER"
    FORBIDDEN = "FORBIDDEN"
    RATE_LIMITED = "RATE_LIMITED"
    SOURCE_MISMATCH = "SOURCE_MISMATCH"
    STALE_TIMESTAMP = "STALE_TIMESTAMP"
    FUTURE_TIMESTAMP = "FUTURE_TIMESTAMP"
    REPLAY = "REPLAY"
    FORMAT_MISMATCH = "FORMAT_MISMATCH"


class WarningCode(StrEnum):
    """Non-fatal sequence anomalies. The message is still accepted."""

    SEQ_GAP = "SEQ_GAP"
    SEQ_RESET = "SEQ_RESET"


PUBLIC_MESSAGES: dict[ReasonCode, str] = {
    ReasonCode.MESSAGE_TOO_LARGE: "Message exceeds the maximum allowed size.",
    ReasonCode.MALFORMED_JSON: "Message body is not valid JSON.",
    ReasonCode.SCHEMA_INVALID: "Message does not match the required envelope.",
    ReasonCode.SIGNATURE_MISSING: "Message signature is missing.",
    ReasonCode.SIGNATURE_INVALID: "Message signature is invalid.",
    ReasonCode.UNKNOWN_SENDER: "Sender is not a recognized layer.",
    ReasonCode.FORBIDDEN: "Caller is not allowed to perform this operation.",
    ReasonCode.RATE_LIMITED: "Too many messages from this source.",
    ReasonCode.SOURCE_MISMATCH: "Canonical source does not match the authenticated sender.",
    ReasonCode.STALE_TIMESTAMP: "Message timestamp is too old.",
    ReasonCode.FUTURE_TIMESTAMP: "Message timestamp is too far in the future.",
    ReasonCode.REPLAY: "This event has already been processed.",
    ReasonCode.FORMAT_MISMATCH: "Content type does not match the declared partner format.",
}

HTTP_STATUS: dict[ReasonCode, int] = {
    ReasonCode.MESSAGE_TOO_LARGE: 413,
    ReasonCode.MALFORMED_JSON: 422,
    ReasonCode.SCHEMA_INVALID: 422,
    ReasonCode.SIGNATURE_MISSING: 401,
    ReasonCode.SIGNATURE_INVALID: 401,
    ReasonCode.UNKNOWN_SENDER: 401,
    ReasonCode.FORBIDDEN: 403,
    ReasonCode.RATE_LIMITED: 429,
    ReasonCode.SOURCE_MISMATCH: 403,
    ReasonCode.STALE_TIMESTAMP: 422,
    ReasonCode.FUTURE_TIMESTAMP: 422,
    ReasonCode.REPLAY: 409,
    ReasonCode.FORMAT_MISMATCH: 415,
}


class SecurityRejection(Exception):
    """Raised when a message must not enter Guardian.

    ``detail`` is safe to log. ``to_public_dict`` is safe to return to a partner.
    """

    def __init__(
        self,
        code: ReasonCode,
        *,
        event_id: str | None = None,
        fields: list[str] | None = None,
        source: str | None = None,
        detail: str | None = None,
    ) -> None:
        self.code = code
        self.event_id = event_id
        self.fields = list(fields) if fields else None
        self.source = source
        self.detail = detail or PUBLIC_MESSAGES[code]
        self.public_message = PUBLIC_MESSAGES[code]
        self.http_status = HTTP_STATUS[code]
        super().__init__(self.detail)

    def to_public_dict(self) -> dict[str, object]:
        body: dict[str, object] = {
            "error": self.code.value,
            "message": self.public_message,
        }
        if self.event_id is not None:
            body["event_id"] = self.event_id
        if self.code is ReasonCode.SCHEMA_INVALID and self.fields:
            body["fields"] = list(self.fields)
        return body


class SecurityConfigurationError(Exception):
    """Guardian cannot start. The message must never contain a secret value."""
