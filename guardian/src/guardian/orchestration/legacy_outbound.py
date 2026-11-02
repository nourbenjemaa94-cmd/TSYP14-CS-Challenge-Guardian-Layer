"""Signs every verdict and containment command Guardian sends.

The sender creates the event id, a monotonic sequence number, and a UTC
timestamp, then ``SecurityGate.sign_outbound`` adds the Guardian HMAC.
Outbound sequence numbers start at 0 for this process.

TODO(security): ASSUMPTION — the Twin verifies isolation commands and the
Brain verifies trust verdicts. This module only guarantees that Guardian
signs them before they are handed to an adapter.
"""

import secrets
import threading
from collections.abc import Callable
from datetime import datetime
from typing import Any

from guardian.security.freshness import format_timestamp
from guardian.security.gate import SecurityGate


class OutboundSigner:
    """Builds a Guardian envelope and signs it with the Guardian key."""

    def __init__(
        self,
        gate: SecurityGate,
        *,
        clock: Callable[[], datetime],
        event_ids: Callable[[], str] | None = None,
    ) -> None:
        self.gate = gate
        self.clock = clock
        self._event_ids = event_ids or _new_event_id
        self._next = 0
        self._lock = threading.Lock()

    def sign(
        self,
        *,
        message_type: str,
        payload: dict[str, Any],
        zone_id: str | None = None,
        device_id: str | None = None,
        event_id: str | None = None,
        seq: int | None = None,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            if seq is None:
                assigned = self._next
                self._next += 1
            else:
                assigned = seq
        source: dict[str, str] = {"layer": "guardian"}
        if device_id is not None:
            source["device_id"] = device_id
        envelope: dict[str, Any] = {
            "schema_version": f"{self.gate.settings.schema_major}.0",
            "event_id": event_id or self._event_ids(),
            "seq": assigned,
            "timestamp": timestamp or format_timestamp(self.clock()),
            "source": source,
            "type": message_type,
            "payload": payload,
        }
        if zone_id is not None:
            envelope["zone_id"] = zone_id
        return self.gate.sign_outbound(envelope)


def _new_event_id() -> str:
    return "evt-" + secrets.token_hex(8)
