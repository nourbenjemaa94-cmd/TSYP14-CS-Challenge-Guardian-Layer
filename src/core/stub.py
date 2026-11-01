"""Stand-in for Guardian core until history, trust, and containment land.

TODO(security): ASSUMPTION — the core does not yet expose ``handle`` or
``on_security_signal``. This stub records envelopes so the pipeline can be
demonstrated. Verdicts are machine-readable enums (``INSUFFICIENT_DATA``,
``UNKNOWN``) with reason code ``CORE_STUB``. Floods are audited only.
"""

import copy
from typing import Any


class StubCore:
    """Records accepted envelopes and returns an explicit stub result."""

    def __init__(self) -> None:
        self.received: list[dict[str, Any]] = []

    def handle(self, envelope: dict[str, Any], warnings: list[Any]) -> dict[str, Any]:
        self.received.append(
            {"envelope": copy.deepcopy(envelope), "warnings": list(warnings)}
        )
        message_type = envelope.get("type")
        payload = envelope.get("payload") if isinstance(envelope.get("payload"), dict) else {}
        zone_id = envelope.get("zone_id")
        if message_type == "verdict_request":
            event_ids = payload.get("event_ids")
            return {
                "type": "trust_verdict",
                "zone_id": zone_id if isinstance(zone_id, str) else None,
                "payload": {
                    "event_ids": list(event_ids) if isinstance(event_ids, list) else [],
                    "verdict": "INSUFFICIENT_DATA",
                    "reason_code": "CORE_STUB",
                },
            }
        if message_type == "device_status_request":
            return {
                "type": "device_status",
                "zone_id": zone_id if isinstance(zone_id, str) else None,
                "payload": {
                    "device_id": payload.get("device_id"),
                    "status": "UNKNOWN",
                    "reason_code": "CORE_STUB",
                },
            }
        return {
            "type": "ingestion_ack",
            "zone_id": zone_id if isinstance(zone_id, str) else None,
            "payload": {"status": "ACCEPTED", "reason_code": "CORE_STUB"},
        }
