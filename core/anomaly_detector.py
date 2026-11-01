from __future__ import annotations

from dataclasses import dataclass, field, fields, replace
from datetime import timedelta
from typing import Any, Dict, List, Mapping, Optional, Tuple

from core.history import HistoryTracker, Reading, ReadingError

HARD = "hard"
SOFT = "soft"

SEVERITY: Dict[str, str] = {
    "SUDDEN_SPIKE_DETECTED": HARD,
    "PHYSICAL_BOUNDS_VIOLATION": HARD,
    "UNIT_MISMATCH": HARD,
    "PERSISTENT_ANOMALY": HARD,
    "MISSING_OR_INVALID_VALUE": HARD,
    "MALFORMED_MESSAGE": HARD,
    "INVALID_SENSOR_ID": HARD,
    "INVALID_METRIC": HARD,
    "INVALID_TIMESTAMP": HARD,
    "INVALID_EVENT_ID": HARD,
    "INVALID_UNIT": HARD,
    "TOO_MANY_SENSORS": HARD,
    "SUSPECTED_SPIKE": SOFT,
    "SENSOR_FROZEN_STAGNANT": SOFT,
    "PHYSICAL_INCOHERENCE": SOFT,
    "TIMESTAMP_REGRESSION": SOFT,
    "UNKNOWN_METRIC": SOFT,
    "DUPLICATE_EVENT": SOFT,
}

MESSAGE_ONLY_CODES = frozenset({
    "MALFORMED_MESSAGE", "INVALID_SENSOR_ID", "INVALID_METRIC", "INVALID_TIMESTAMP",
    "INVALID_EVENT_ID", "INVALID_UNIT", "MISSING_OR_INVALID_VALUE", "TOO_MANY_SENSORS",
    "DUPLICATE_EVENT",
})


def severity_of(code: str) -> str:
    return SEVERITY.get(code, SOFT)


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str = ""

    @property
    def severity(self) -> str:
        return severity_of(self.code)

    def to_dict(self) -> Dict[str, str]:
        return {"code": self.code, "severity": self.severity, "detail": self.detail}


@dataclass(frozen=True)
class DetectionResult:
    event_id: str
    sensor_id: str
    metric: str
    timestamp: str
    findings: Tuple[Finding, ...] = ()
    recorded: bool = False

    @property
    def codes(self) -> List[str]:
        seen: List[str] = []
        for finding in self.findings:
            if finding.code not in seen:
                seen.append(finding.code)
        return seen

    @property
    def has_hard(self) -> bool:
        return any(f.severity == HARD for f in self.findings)

    @property
    def primary_code(self) -> Optional[str]:
        for finding in self.findings:
            if finding.severity == HARD:
                return finding.code
        return self.findings[0].code if self.findings else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id, "sensor_id": self.sensor_id, "metric": self.metric,
            "timestamp": self.timestamp, "recorded": self.recorded,
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_codes(cls, msg: Any, codes: List[str]) -> "DetectionResult":
        data = msg if isinstance(msg, Mapping) else {}
        return cls(
            event_id=str(data.get("event_id") or ""),
            sensor_id=str(data.get("sensor_id") or "unknown"),
            metric=str(data.get("metric") or ""),
            timestamp=str(data.get("timestamp") or ""),
            findings=tuple(Finding(c) for c in codes),
            recorded=not any(c in MESSAGE_ONLY_CODES for c in codes),
        )


@dataclass(frozen=True)
class MetricLimits:
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    max_rate_per_sec: Optional[float] = None
    min_dt_sec: float = 1.0
    stuck_count: int = 0
    stuck_tolerance: float = 0.0
    unit: str = ""

    def __post_init__(self) -> None:
        if self.min_dt_sec <= 0 or self.stuck_count < 0 or self.stuck_count == 1:
            raise ValueError("min_dt_sec must be > 0 and stuck_count must be 0 or >= 2")
        if self.min_value is not None and self.max_value is not None and self.min_value > self.max_value:
            raise ValueError("min_value must be <= max_value")


@dataclass(frozen=True)
class CorrelationRule:
    metric: str = "water_level"
    trigger_above: float = 150.0
    supporters: Tuple[Tuple[str, float], ...] = (("camera_flood_score", 0.5), ("emergency_calls", 1.0))
    min_supporters: int = 1
    window_sec: float = 120.0


def default_metrics() -> Dict[str, MetricLimits]:
    return {
        "water_level": MetricLimits(0.0, 1000.0, 15.0, 1.0, 10, 0.0, "cm"),
        "traffic_density": MetricLimits(0.0, 500.0, 50.0, 1.0, 10),
        "power_load": MetricLimits(0.0, 100000.0, 5000.0, 1.0, 10),
        "air_quality": MetricLimits(0.0, 500.0, 50.0, 1.0, 10),
        "emergency_calls": MetricLimits(0.0, 1000.0),
        "camera_flood_score": MetricLimits(0.0, 1.0),
    }


_ALIASES = {
    "max_physical_limit_cm": "max_value",
    "min_physical_limit_cm": "min_value",
    "max_rate_of_change_cm_per_sec": "max_rate_per_sec",
}


@dataclass(frozen=True)
class DetectorConfig:
    persistence_readings: int = 3
    hard_rate_factor: float = 3.0
    metrics: Mapping[str, MetricLimits] = field(default_factory=default_metrics)
    correlations: Tuple[CorrelationRule, ...] = (CorrelationRule(),)

    def __post_init__(self) -> None:
        if self.persistence_readings < 1 or self.hard_rate_factor < 1:
            raise ValueError("persistence_readings must be >= 1 and hard_rate_factor >= 1")

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "DetectorConfig":
        base = cls()
        kwargs: Dict[str, Any] = {}
        for key in ("persistence_readings", "hard_rate_factor"):
            if key in data:
                kwargs[key] = type(getattr(base, key))(data[key])
        metrics = dict(base.metrics)
        correlations = base.correlations
        allowed = {f.name for f in fields(MetricLimits)}
        for name, section in data.items():
            if not isinstance(section, Mapping):
                continue
            values = {_ALIASES.get(k, k): v for k, v in section.items() if _ALIASES.get(k, k) in allowed}
            if values:
                metrics[name] = replace(metrics.get(name, MetricLimits()), **values)
            if name == "water_level" and "spike_threshold_cm" in section:
                trigger = float(section["spike_threshold_cm"])
                correlations = tuple(
                    replace(r, trigger_above=trigger) if r.metric == "water_level" else r for r in correlations
                )
        return cls(metrics=metrics, correlations=correlations, **kwargs)


class AnomalyDetector:
    def __init__(
        self,
        config: Optional[DetectorConfig] = None,
        history: Optional[HistoryTracker] = None,
        *,
        water_spike_threshold_cm: Optional[float] = None,
        min_water_level_cm: Optional[float] = None,
        max_water_level_cm: Optional[float] = None,
    ) -> None:
        cfg = config or DetectorConfig()
        if min_water_level_cm is not None or max_water_level_cm is not None:
            metrics = dict(cfg.metrics)
            limits = metrics.get("water_level", MetricLimits())
            metrics["water_level"] = replace(
                limits,
                min_value=limits.min_value if min_water_level_cm is None else min_water_level_cm,
                max_value=limits.max_value if max_water_level_cm is None else max_water_level_cm,
            )
            cfg = replace(cfg, metrics=metrics)
        if water_spike_threshold_cm is not None:
            cfg = replace(cfg, correlations=tuple(
                replace(r, trigger_above=water_spike_threshold_cm) if r.metric == "water_level" else r
                for r in cfg.correlations
            ))
        self.config = cfg
        self.history = history if history is not None else HistoryTracker()

    def detect(self, canonical_msg: Dict[str, Any], history: Optional[List[Dict[str, Any]]] = None) -> List[str]:
        return self.analyze(canonical_msg).codes

    def analyze(self, canonical_msg: Any) -> DetectionResult:
        try:
            reading = Reading.from_message(canonical_msg)
        except ReadingError as exc:
            return self._rejected(canonical_msg, exc)

        if self.history.has_event(reading.event_id):
            return self._result(reading, [Finding("DUPLICATE_EVENT", "event_id was already processed")], False)

        findings: List[Finding] = []
        limits = self.config.metrics.get(reading.metric)
        corroboration = self._corroboration(reading)
        if limits is None:
            findings.append(Finding("UNKNOWN_METRIC", f"no limits configured for metric '{reading.metric}'"))
        else:
            findings += self._check_limits(reading, limits, corroboration)
        if corroboration is False:
            findings.append(Finding("PHYSICAL_INCOHERENCE", "correlated sensors do not confirm this reading"))
        findings += self._persistence(reading, findings)

        recorded = True
        try:
            self.history.record(reading, tuple(f.code for f in findings))
        except ReadingError as exc:
            findings.append(Finding(exc.code, exc.message))
            recorded = False
        return self._result(reading, findings, recorded)

    def _check_limits(self, reading: Reading, limits: MetricLimits, corroboration: Optional[bool]) -> List[Finding]:
        value = reading.value
        if limits.unit and reading.unit and reading.unit != limits.unit:
            return [Finding("UNIT_MISMATCH", f"expected '{limits.unit}', got '{reading.unit}'")]
        if (limits.min_value is not None and value < limits.min_value) or (
            limits.max_value is not None and value > limits.max_value
        ):
            return [Finding("PHYSICAL_BOUNDS_VIOLATION",
                            f"{value} outside [{limits.min_value}, {limits.max_value}]")]
        findings: List[Finding] = []
        reference = self.history.reference(reading.sensor_id)
        if reference is not None and limits.max_rate_per_sec is not None:
            previous = self.history.entries(reading.sensor_id)[-1]
            gap = (reading.ts - previous.reading.ts).total_seconds()
            if gap < 0:
                findings.append(Finding("TIMESTAMP_REGRESSION", "reading is older than the previous reading"))
            rate = abs(value - reference.reading.value) / max(gap, limits.min_dt_sec)
            if rate > limits.max_rate_per_sec and corroboration is not True:
                code = "SUDDEN_SPIKE_DETECTED" if rate > self.config.hard_rate_factor * limits.max_rate_per_sec \
                    else "SUSPECTED_SPIKE"
                findings.append(Finding(
                    code, f"{reference.reading.value} -> {value} is {rate:.1f}/s, limit {limits.max_rate_per_sec}/s"))
        if limits.stuck_count:
            recent = self.history.last_values(reading.sensor_id, limits.stuck_count - 1) + [value]
            if len(recent) == limits.stuck_count and max(recent) - min(recent) <= limits.stuck_tolerance:
                findings.append(Finding("SENSOR_FROZEN_STAGNANT", f"{limits.stuck_count} identical readings in a row"))
        return findings

    def _corroboration(self, reading: Reading) -> Optional[bool]:
        verdict: Optional[bool] = None
        for rule in self.config.correlations:
            if rule.metric != reading.metric or reading.value < rule.trigger_above:
                continue
            start = reading.ts - timedelta(seconds=rule.window_sec)
            supported = contradicting = 0
            for metric, threshold in rule.supporters:
                others = self.history.recent(metric, start, reading.ts, reading.sensor_id)
                if not others:
                    continue
                if any(o.value >= threshold for o in others):
                    supported += 1
                else:
                    contradicting += 1
            if supported >= rule.min_supporters:
                verdict = True
            elif contradicting > 0:
                return False
        return verdict

    def _persistence(self, reading: Reading, findings: List[Finding]) -> List[Finding]:
        for finding in findings:
            if finding.severity != SOFT:
                continue
            streak = self.history.soft_streak(reading.sensor_id, finding.code) + 1
            if streak >= self.config.persistence_readings:
                return [Finding("PERSISTENT_ANOMALY", f"{finding.code} on {streak} consecutive readings")]
        return []

    @staticmethod
    def _result(reading: Reading, findings: List[Finding], recorded: bool) -> DetectionResult:
        return DetectionResult(reading.event_id, reading.sensor_id, reading.metric,
                               reading.ts.isoformat(), tuple(findings), recorded)

    @staticmethod
    def _rejected(msg: Any, error: ReadingError) -> DetectionResult:
        data = msg if isinstance(msg, Mapping) else {}
        sensor_id, event_id = data.get("sensor_id"), data.get("event_id")
        ok_sensor = isinstance(sensor_id, str) and 0 < len(sensor_id) <= 64
        return DetectionResult(
            event_id=event_id[:128] if isinstance(event_id, str) else "",
            sensor_id=sensor_id if ok_sensor else "unknown",
            metric="", timestamp="", findings=(Finding(error.code, error.message),), recorded=False,
        )