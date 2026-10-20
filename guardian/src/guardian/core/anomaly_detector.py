"""
core/anomaly_detector.py
------------------------
Cyber-physical anomaly and spoofing detector (Member 3 & 4: Ghaith Mnasri & Rayen Saidi).
Detects:
1. Sudden flood spikes (e.g. water level jumping to extreme values)
2. Physical incoherence (impossible rates of change or out-of-boundary limits)
3. Stagnant or frozen sensors (dead sensor hardware)
"""

from typing import Dict, List, Any
try:
    from core.history import HistoryTracker
except ImportError:
    from .history import HistoryTracker


class AnomalyDetector:
    """
    Evaluates canonical telemetry messages against historical context and physical models.
    Returns a list of anomaly flag codes.
    """

    def __init__(
        self,
        water_spike_threshold_cm: float = 200.0,
        max_rate_of_change_cm: float = 100.0,
        min_water_level_cm: float = 0.0,
        max_water_level_cm: float = 1000.0
    ):
        self.water_spike_threshold_cm = water_spike_threshold_cm
        self.max_rate_of_change_cm = max_rate_of_change_cm
        self.min_water_level_cm = min_water_level_cm
        self.max_water_level_cm = max_water_level_cm
        self.history_tracker = HistoryTracker()

    def detect(self, canonical_msg: Dict[str, Any], history: List[Dict[str, Any]]) -> List[str]:
        """
        Detects anomalies in the canonical message based on value thresholds and history.
        Complies strictly with Requirement R3 specifications.
        """
        flags: List[str] = []
        value = canonical_msg.get("value")

        if value is None or not isinstance(value, (int, float)):
            return ["MISSING_OR_INVALID_VALUE"]

        val_float = float(value)

        # 1. Physical Bounds Check
        if val_float < self.min_water_level_cm or val_float > self.max_water_level_cm:
            flags.append("PHYSICAL_BOUNDS_VIOLATION")

        # 2. Sudden Spike Detection (Fake Flood scenario)
        if val_float > self.water_spike_threshold_cm:
            if "SUDDEN_SPIKE_DETECTED" not in flags:
                flags.append("SUDDEN_SPIKE_DETECTED")
            if "PHYSICAL_INCOHERENCE" not in flags:
                flags.append("PHYSICAL_INCOHERENCE")

        # 3. Dynamic Rate-of-Change Check against history
        if history:
            prev_value = self.history_tracker.get_latest_value(history)
            if prev_value is not None:
                delta = abs(val_float - prev_value)
                if delta > self.max_rate_of_change_cm and "SUDDEN_SPIKE_DETECTED" not in flags:
                    flags.append("SUDDEN_SPIKE_DETECTED")

            # 4. Sensor Frozen / Dead Hardware Check
            if self.history_tracker.is_sensor_frozen(history, count_threshold=10):
                flags.append("SENSOR_FROZEN_STAGNANT")

        return flags

