"""
audit/event_store.py
--------------------
Telemetry event store and sliding window historical buffer.
Maintains sensor historical readings to enable anomaly detection and trust evaluation.
"""

from collections import defaultdict
from typing import Any


class EventStore:
    """
    Stores and manages historical sensor readings and audit records.
    Provides sliding window lookups for anomaly detection.
    """

    def __init__(self, max_history_per_sensor: int = 100):
        self.max_history = max_history_per_sensor
        self._history: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._audit_records: list[dict[str, Any]] = []

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
        """Stores a permanent audit record for post-incident forensic analysis."""
        self._audit_records.append(audit_entry)

    def get_all_readings(self) -> dict[str, list[dict[str, Any]]]:
        """Returns snapshot of all sensor histories."""
        return {k: list(v) for k, v in self._history.items()}

    def clear(self) -> None:
        """Resets the store (used for test setup/teardown)."""
        self._history.clear()
        self._audit_records.clear()


# Default singleton instance
default_event_store = EventStore()

