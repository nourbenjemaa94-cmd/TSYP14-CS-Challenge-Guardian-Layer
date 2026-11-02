"""
audit/event_store.py
--------------------
Telemetry event store and sliding window historical buffer.
Maintains sensor historical readings to enable anomaly detection and trust evaluation.
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict


class EventStore:
    """
    Stores and manages historical sensor readings and audit records.
    Provides sliding window lookups for anomaly detection.
    """

    def __init__(self, max_history_per_sensor: int = 100):
        self.max_history = max_history_per_sensor
        self._history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._audit_records: List[Dict[str, Any]] = []

    def get_history(self, sensor_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves the recorded telemetry readings for a specific sensor.
        If no readings exist, returns an empty list or default baseline.
        """
        return list(self._history.get(sensor_id, []))

    def add_reading(self, sensor_id: str, reading: Dict[str, Any]) -> None:
        """
        Appends a canonical telemetry reading to the sensor's historical window.
        Enforces maximum history buffer size.
        """
        sensor_readings = self._history[sensor_id]
        sensor_readings.append(reading)
        if len(sensor_readings) > self.max_history:
            sensor_readings.pop(0)

    def record_audit(self, audit_entry: Dict[str, Any]) -> None:
        """Stores a permanent audit record for post-incident forensic analysis."""
        self._audit_records.append(audit_entry)

    def get_all_readings(self) -> Dict[str, List[Dict[str, Any]]]:
        """Returns snapshot of all sensor histories."""
        return {k: list(v) for k, v in self._history.items()}

    def clear(self) -> None:
        """Resets the store (used for test setup/teardown)."""
        self._history.clear()
        self._audit_records.clear()


# Default singleton instance
default_event_store = EventStore()

