"""Replay cache and per-source sequence tracking.

The event-id cache covers one freshness window, so a duplicate inside that
window is refused. Sequence gaps and resets are warnings: they are visible,
but they are not by themselves proof of a forged message. State changes only
after the message has passed every earlier check, and a rejected replay does
not move the sequence counter.

TODO(security): ASSUMPTION — sequence numbers are per source (layer + device),
may start at any non-negative value, and then increase by 1. A gap is
``SEQ_GAP``. A number that does not move forward is ``SEQ_RESET``, and the
stored sequence adopts that new value so a restarted device can continue.
"""

import threading
from datetime import datetime

from guardian.security.errors import ReasonCode, SecurityRejection, WarningCode


class ReplayProtector:
    """In-memory replay and sequence state for a single Guardian process."""

    def __init__(self, *, window_seconds: float) -> None:
        self._window = window_seconds
        self._seen: dict[tuple[str, str], datetime] = {}
        self._last_seq: dict[str, int] = {}
        self._lock = threading.Lock()

    def observe(
        self,
        *,
        source_key: str,
        event_id: str,
        seq: int,
        now: datetime,
    ) -> list[WarningCode]:
        """Record a new event or raise ``REPLAY``. Returns sequence warnings."""
        with self._lock:
            self._evict(now)
            cache_key = (source_key, event_id)
            if cache_key in self._seen:
                raise SecurityRejection(
                    ReasonCode.REPLAY,
                    event_id=event_id,
                    source=source_key,
                    detail="Duplicate event_id inside the freshness window.",
                )
            warnings: list[WarningCode] = []
            last = self._last_seq.get(source_key)
            if last is not None:
                if seq > last + 1:
                    warnings.append(WarningCode.SEQ_GAP)
                elif seq <= last:
                    warnings.append(WarningCode.SEQ_RESET)
            self._seen[cache_key] = now
            self._last_seq[source_key] = seq
            return warnings

    def _evict(self, now: datetime) -> None:
        expired = [
            key
            for key, seen_at in self._seen.items()
            if (now - seen_at).total_seconds() > self._window
        ]
        for key in expired:
            del self._seen[key]
