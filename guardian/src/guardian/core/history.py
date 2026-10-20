"""
core/history.py
---------------
History analysis, statistical baselines, and trend calculations (Member 3 & 4).
"""

from typing import List, Dict, Any, Optional
import math


class HistoryTracker:
    """
    Analyzes historical readings to establish baselines, calculate moving averages,
    and detect sensor flatlines or abnormal drift.
    """

    def __init__(self, window_size: int = 20):
        self.window_size = window_size

    def calculate_mean(self, history: List[Dict[str, Any]]) -> Optional[float]:
        """Calculates arithmetic mean of recent sensor readings."""
        values = [r.get("value") for r in history if isinstance(r.get("value"), (int, float))]
        if not values:
            return None
        return sum(values) / len(values)

    def calculate_std_dev(self, history: List[Dict[str, Any]]) -> Optional[float]:
        """Calculates standard deviation of historical values."""
        values = [r.get("value") for r in history if isinstance(r.get("value"), (int, float))]
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return math.sqrt(variance)

    def get_latest_value(self, history: List[Dict[str, Any]]) -> Optional[float]:
        """Returns the most recent reading value from history."""
        if not history:
            return None
        latest = history[-1]
        val = latest.get("value")
        return float(val) if isinstance(val, (int, float)) else None

    def calculate_delta(self, current_value: float, history: List[Dict[str, Any]]) -> float:
        """Calculates absolute change between current value and previous reading."""
        prev = self.get_latest_value(history)
        if prev is None:
            return 0.0
        return abs(current_value - prev)

    def is_sensor_frozen(self, history: List[Dict[str, Any]], count_threshold: int = 5) -> bool:
        """
        Detects if a sensor is stuck/dead reporting exact identical values.
        """
        if len(history) < count_threshold:
            return False
        recent = [r.get("value") for r in history[-count_threshold:]]
        return len(set(recent)) == 1 and recent[0] is not None

