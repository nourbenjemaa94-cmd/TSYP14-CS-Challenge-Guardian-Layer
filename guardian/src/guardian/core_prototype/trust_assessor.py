"""
core/trust_assessor.py
----------------------
Trust assessment engine (Member 3 & 4: Ghaith Mnasri & Rayen Saidi).
Computes trust scores, assigns trust verdicts (TRUSTED, SUSPICIOUS, UNTRUSTED),
and provides audit reason codes.
"""

from typing import Dict, List, Any, Tuple


class TrustAssessor:
    """
    Evaluates trustworthiness of incoming sensor data using anomaly flags
    and sensor reliability criteria.
    """

    def __init__(self, untrusted_penalty: float = 0.6):
        self.untrusted_penalty = untrusted_penalty

    def assess(self, canonical_msg: Dict[str, Any], flags: List[str]) -> Tuple[str, str]:
        """
        Assesses canonical telemetry and outputs (verdict, reason).
        
        Verdicts:
        - "TRUSTED": No anomalies detected, reading conforms to expected physical model.
        - "UNTRUSTED": Severe anomaly, physical violation, or spoofing detected.
        - "SUSPICIOUS": Minor degradation or warning-level indicator.
        """
        if not flags:
            return "TRUSTED", "NORMAL"

        # Check for severe anomalies
        severe_flags = {
            "SUDDEN_SPIKE_DETECTED",
            "PHYSICAL_INCOHERENCE",
            "PHYSICAL_BOUNDS_VIOLATION",
            "MISSING_OR_INVALID_VALUE"
        }

        if any(f in severe_flags for f in flags):
            return "UNTRUSTED", "ANOMALY_DETECTED"

        # Warning flags return SUSPICIOUS
        return "SUSPICIOUS", "DEGRADED_CONFIDENCE"

