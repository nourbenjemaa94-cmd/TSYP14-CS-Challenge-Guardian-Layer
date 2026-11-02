from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Mapping, Optional, Tuple

from core.anomaly_detector import DetectionResult, Finding, HARD
from core.history import SUSPICIOUS, TRUSTED, UNTRUSTED, HistoryTracker, VerdictRecord

_LEGACY_REASON = {TRUSTED: "NORMAL", SUSPICIOUS: "DEGRADED_CONFIDENCE", UNTRUSTED: "ANOMALY_DETECTED"}


def _default_penalties() -> Dict[str, float]:
    return {
        "SUDDEN_SPIKE_DETECTED": 0.8, "PHYSICAL_BOUNDS_VIOLATION": 1.0, "UNIT_MISMATCH": 1.0,
        "PERSISTENT_ANOMALY": 0.8, "SUSPECTED_SPIKE": 0.5, "SENSOR_FROZEN_STAGNANT": 0.5,
        "PHYSICAL_INCOHERENCE": 0.5, "TIMESTAMP_REGRESSION": 0.3, "UNKNOWN_METRIC": 0.5,
        "DUPLICATE_EVENT": 0.4,
    }


@dataclass(frozen=True)
class TrustConfig:
    untrusted_below: float = 0.4
    suspicious_below: float = 0.7
    penalties: Mapping[str, float] = field(default_factory=_default_penalties)
    hard_default_penalty: float = 0.8
    soft_default_penalty: float = 0.5
    recovery_clean_readings: int = 3
    full_confidence_readings: int = 10
    policy_version: str = "1.0"

    def __post_init__(self) -> None:
        if not 0.0 <= self.untrusted_below <= self.suspicious_below <= 1.0:
            raise ValueError("need 0 <= untrusted_below <= suspicious_below <= 1")
        if self.recovery_clean_readings < 0 or self.full_confidence_readings < 1:
            raise ValueError("recovery_clean_readings must be >= 0 and full_confidence_readings >= 1")

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "TrustConfig":
        base = cls()
        values: Dict[str, Any] = {}
        for src, dst in (("isolate_threshold", "untrusted_below"), ("quarantine_threshold", "suspicious_below")):
            if src in data:
                values[dst] = float(data[src])
        for key in ("recovery_clean_readings", "full_confidence_readings"):
            if key in data:
                values[key] = int(data[key])
        if "policy_version" in data:
            values["policy_version"] = str(data["policy_version"])
        return replace(base, **values)


@dataclass(frozen=True)
class TrustVerdict:
    event_id: str
    sensor_id: str
    verdict: str
    confidence: float
    reason_code: str
    reason: str
    score: float
    assessment_id: str
    policy_version: str
    timestamp: str
    evidence: Tuple[Dict[str, str], ...] = ()
    recorded: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id, "sensor_id": self.sensor_id, "verdict": self.verdict,
            "confidence": self.confidence, "reason_code": self.reason_code, "reason": self.reason,
            "score": self.score, "assessment_id": self.assessment_id,
            "policy_version": self.policy_version, "timestamp": self.timestamp,
            "evidence": [dict(e) for e in self.evidence],
        }


class TrustAssessor:
    def __init__(
        self,
        config: Optional[TrustConfig] = None,
        history: Optional[HistoryTracker] = None,
        *,
        untrusted_penalty: Optional[float] = None,
    ) -> None:
        cfg = config or TrustConfig()
        if untrusted_penalty is not None:
            cfg = replace(cfg, hard_default_penalty=untrusted_penalty)
        self.config = cfg
        self.history = history if history is not None else HistoryTracker()
        self._sequence = 0

    def assess(self, canonical_msg: Dict[str, Any], flags: List[str]) -> Tuple[str, str]:
        verdict = self.evaluate(DetectionResult.from_codes(canonical_msg, list(flags)))
        return verdict.verdict, verdict.reason

    def evaluate(self, detection: DetectionResult) -> TrustVerdict:
        cfg = self.config
        score = round(max(0.0, 1.0 - sum(self._penalty(f) for f in detection.findings)), 3)
        reason_code = detection.primary_code or "NORMAL"

        if detection.has_hard or score < cfg.untrusted_below:
            verdict = UNTRUSTED
        elif score < cfg.suspicious_below:
            verdict = SUSPICIOUS
        else:
            verdict = TRUSTED
        if verdict == TRUSTED and detection.recorded and self._on_probation(detection.sensor_id):
            verdict, reason_code = SUSPICIOUS, "DEVICE_RECOVERING"

        self._sequence += 1
        result = TrustVerdict(
            event_id=detection.event_id, sensor_id=detection.sensor_id, verdict=verdict,
            confidence=self._confidence(verdict, detection), reason_code=reason_code,
            reason=_LEGACY_REASON[verdict], score=score,
            assessment_id=f"assess-{self._sequence:06d}", policy_version=cfg.policy_version,
            timestamp=detection.timestamp,
            evidence=tuple(f.to_dict() for f in detection.findings), recorded=detection.recorded,
        )
        if detection.recorded:
            self.history.record_verdict(VerdictRecord(
                result.event_id, result.sensor_id, verdict, reason_code, result.confidence, result.timestamp))
        return result

    def device_trust(self, sensor_id: str) -> Tuple[str, str]:
        recent = self.history.verdicts(sensor_id)
        if not recent:
            return SUSPICIOUS, "NO_HISTORY"
        if recent[-1].verdict == UNTRUSTED:
            return UNTRUSTED, recent[-1].reason_code
        if self._on_probation(sensor_id):
            return SUSPICIOUS, "DEVICE_RECOVERING"
        return TRUSTED, "NORMAL"

    def _penalty(self, finding: Finding) -> float:
        default = self.config.hard_default_penalty if finding.severity == HARD else self.config.soft_default_penalty
        return self.config.penalties.get(finding.code, default)

    def _on_probation(self, sensor_id: str) -> bool:
        window = self.history.verdicts(sensor_id, self.config.recovery_clean_readings)
        return any(v.verdict != TRUSTED for v in window)

    def _confidence(self, verdict: str, detection: DetectionResult) -> float:
        count = len(detection.findings)
        if verdict == TRUSTED:
            depth = min(len(self.history.entries(detection.sensor_id)) / self.config.full_confidence_readings, 1.0)
            value = 0.5 + 0.5 * depth
        elif verdict == SUSPICIOUS:
            value = min(0.5 + 0.1 * count, 0.8)
        else:
            value = min(0.7 + 0.1 * count, 0.99)
        return round(value, 3)