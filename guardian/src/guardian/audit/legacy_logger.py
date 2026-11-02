"""Security audit records for the live timeline.

Every rejection and every sequence warning becomes one record. The record
lists who was refused and why. It never contains a key, a signature, or a
payload value.

TODO(security): ASSUMPTION — the audit team has not landed storage yet, so
records are kept in memory and written to the ``guardian.security`` logger.
A flood signal uses outcome ``signal`` because it is not a second rejection
and not a sequence warning.
"""

import logging
from typing import Any

_LOGGER_NAME = "guardian.security"
_FIELDS = ("timestamp", "stage", "outcome", "code", "event_id", "source", "operation")


class AuditLogger:
    """In-memory security audit plus a one-line timeline entry per record."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self.timeline: list[str] = []
        self._log = logging.getLogger(_LOGGER_NAME)

    def record(
        self,
        *,
        timestamp: str,
        stage: str,
        outcome: str,
        code: str,
        event_id: str | None,
        source: str | None,
        operation: str,
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "timestamp": timestamp,
            "stage": stage,
            "outcome": outcome,
            "code": code,
            "event_id": event_id,
            "source": source,
            "operation": operation,
        }
        if tuple(entry) != _FIELDS:
            raise RuntimeError("Audit record fields drifted from the security contract.")
        self.records.append(entry)
        line = _timeline_line(entry)
        self.timeline.append(line)
        self._log.info(
            "timestamp=%s stage=%s outcome=%s code=%s event_id=%s source=%s operation=%s",
            timestamp,
            stage,
            outcome,
            code,
            event_id,
            source,
            operation,
        )
        return entry


def _timeline_line(entry: dict[str, Any]) -> str:
    event_id = entry["event_id"] or "unknown"
    outcome = entry["outcome"]
    code = entry["code"]
    if outcome == "rejected":
        return f"Guardian rejected message {event_id}: {code}"
    if outcome == "accepted_with_warning":
        return f"Guardian accepted message {event_id} with warning {code}"
    if code == "FLOOD_SUSPECTED":
        return f"Guardian flood suspected from {entry['source']}"
    return f"Guardian security event {event_id}: {code}"
