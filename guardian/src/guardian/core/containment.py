"""
core/containment.py
-------------------
Containment policy engine (Member 3 & 4: Ghaith Mnasri & Rayen Saidi).
Enforces active mitigation actions to protect the City Brain (Layer 3)
from compromised, spoofed, or erratic sensor streams.
"""

from typing import List, Dict, Any


class ContainmentEngine:
    """
    Determines containment action based on trust verdict and anomaly flags.
    
    Actions:
    - "ISOLATE": Completely blocks data from reaching City Brain. Protects urban decisions.
    - "QUARANTINE": Routes to sandboxed buffer for further automated analysis.
    - "ALLOW": Permits delivery to City Brain.
    """

    def __init__(self):
        self.isolated_sensors = set()

    def evaluate_action(self, flags: List[str], verdict: str) -> str:
        """
        Determines the appropriate containment policy action.
        """
        if verdict == "UNTRUSTED" or flags:
            return "ISOLATE"
        elif verdict == "SUSPICIOUS":
            return "QUARANTINE"
        return "ALLOW"

    def mark_sensor_isolated(self, sensor_id: str):
        """Adds a sensor to the active hardware isolation blacklist."""
        self.isolated_sensors.add(sensor_id)

    def is_sensor_isolated(self, sensor_id: str) -> bool:
        """Checks if a sensor is currently isolated."""
        return sensor_id in self.isolated_sensors

    def release_sensor(self, sensor_id: str):
        """Removes sensor from isolation after maintenance or reset."""
        self.isolated_sensors.discard(sensor_id)

