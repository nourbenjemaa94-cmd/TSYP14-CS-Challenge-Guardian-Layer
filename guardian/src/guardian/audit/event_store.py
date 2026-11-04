"""
audit/event_store.py
--------------------
Telemetry read model and sliding window historical buffer.

This implementation is deliberately in memory. It is not a durable evidence
store: readings, verdicts, and audit records disappear when the process exits.
"""

from collections import defaultdict
from typing import Any


class EventStore:
    """
    Stores accepted readings as an in-memory application audit/read-model mirror.

    Core decisions use the single injected ``HistoryTracker`` composed in
    ``guardian.main``. This store is retained for audit/API history and must
    not become a second source of anomaly, trust, or containment state.
    """

    def __init__(self, max_history_per_sensor: int = 100):
        self.max_history = max_history_per_sensor
        self._history: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._audit_records: list[dict[str, Any]] = []
        self._verdicts: dict[str, dict[str, Any]] = {}

    def get_history(self, sensor_id: str) -> list[dict[str, Any]]:
        """
        Retrieves the recorded telemetry readings for a specific sensor.
        If no readings exist, returns an empty list or default baseline.
        """
        return list(self._history.get(sensor_id, []))

    def add_reading(self, sensor_id: str, reading: dict[str, Any]) -> None:
        """
        Appends a canonical telemetry reading to the sensor's historical window.
        Enforces maximum history buffer size.
        """
        sensor_readings = self._history[sensor_id]
        sensor_readings.append(reading)
        if len(sensor_readings) > self.max_history:
            sensor_readings.pop(0)

    def record_audit(self, audit_entry: dict[str, Any]) -> None:
        """Keep an in-memory audit record; durable evidence needs an external store."""
        self._audit_records.append(audit_entry)

    def record_verdict(self, event_id: str, verdict: dict[str, Any]) -> None:
        """Persist the latest Core verdict for signed Brain queries."""
        import copy

        self._verdicts[event_id] = copy.deepcopy(verdict)

    def get_verdict(self, event_id: str) -> dict[str, Any] | None:
        """Return a defensive copy of a persisted verdict, if known."""
        import copy

        verdict = self._verdicts.get(event_id)
        return copy.deepcopy(verdict) if verdict is not None else None

    def get_all_readings(self) -> dict[str, list[dict[str, Any]]]:
        """Returns snapshot of all sensor histories."""
        return {k: list(v) for k, v in self._history.items()}

    def clear(self) -> None:
        """Resets the store (used for test setup/teardown)."""
        self._history.clear()
        self._audit_records.clear()
        self._verdicts.clear()


# Default singleton instance
default_event_store = EventStore()

