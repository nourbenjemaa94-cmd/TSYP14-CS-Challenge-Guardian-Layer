from __future__ import annotations

import math
import re
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

TRUSTED = "TRUSTED"
SUSPICIOUS = "SUSPICIOUS"
UNTRUSTED = "UNTRUSTED"

_ID_RE = re.compile(r"[A-Za-z0-9_.:\-]{1,64}")


class ReadingError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ReadingError(
                "INVALID_TIMESTAMP",
                f"not an ISO 8601 timestamp: {value[:40]!r}",
            ) from exc
    else:
        raise ReadingError("INVALID_TIMESTAMP", "timestamp is missing or not a string")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class Reading:
    event_id: str
    sensor_id: str
    metric: str
    value: float
    unit: str
    ts: datetime

    @classmethod
    def from_message(cls, msg: Any) -> Reading:
        if not isinstance(msg, Mapping):
            raise ReadingError("MALFORMED_MESSAGE", "reading must be a JSON object")
        sensor_id = msg.get("sensor_id")
        if not isinstance(sensor_id, str) or not _ID_RE.fullmatch(sensor_id):
            raise ReadingError("INVALID_SENSOR_ID", "sensor_id must be 1-64 chars of letters, digits, _ . : -")
        metric = msg.get("metric")
        if not isinstance(metric, str) or not _ID_RE.fullmatch(metric):
            raise ReadingError("INVALID_METRIC", "metric must be 1-64 chars of letters, digits, _ . : -")
        value = msg.get("value")
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ReadingError("MISSING_OR_INVALID_VALUE", "value must be a finite number")
        ts = parse_timestamp(msg.get("timestamp"))
        event_id = msg.get("event_id") or ""
        if not isinstance(event_id, str) or len(event_id) > 128:
            raise ReadingError("INVALID_EVENT_ID", "event_id must be a string of at most 128 chars")
        unit = msg.get("unit") or ""
        if not isinstance(unit, str) or len(unit) > 16:
            raise ReadingError("INVALID_UNIT", "unit must be a string of at most 16 chars")
        return cls(event_id, sensor_id, metric, float(value), unit, ts)


@dataclass
class HistoryEntry:
    reading: Reading
    codes: tuple[str, ...] = ()
    verdict: str | None = None
    rolled_back: bool = False

    @property
    def clean(self) -> bool:
        return not self.codes and not self.rolled_back


@dataclass(frozen=True)
class VerdictRecord:
    event_id: str
    sensor_id: str
    verdict: str
    reason_code: str
    confidence: float
    timestamp: str


class HistoryTracker:
    def __init__(self, window_size: int = 20, verdict_window: int = 20, max_sensors: int = 1000) -> None:
        if window_size < 2 or verdict_window < 1 or max_sensors < 1:
            raise ValueError("window_size must be >= 2, verdict_window >= 1, max_sensors >= 1")
        self.window_size = window_size
        self.verdict_window = verdict_window
        self.max_sensors = max_sensors
        self._readings: dict[str, deque[HistoryEntry]] = {}
        self._verdicts: dict[str, deque[VerdictRecord]] = {}

    def record(self, reading: Reading, codes: tuple[str, ...] = ()) -> HistoryEntry:
        window = self._readings.get(reading.sensor_id)
        if window is None:
            if len(self._readings) >= self.max_sensors:
                raise ReadingError("TOO_MANY_SENSORS", f"sensor limit of {self.max_sensors} reached")
            window = self._readings[reading.sensor_id] = deque(maxlen=self.window_size)
        entry = HistoryEntry(reading, tuple(codes))
        window.append(entry)
        return entry

    def entries(self, sensor_id: str) -> list[HistoryEntry]:
        return list(self._readings.get(sensor_id, ()))

    def sensors(self) -> list[str]:
        return sorted(self._readings)

    def find_entry(self, event_id: str) -> HistoryEntry | None:
        if not event_id:
            return None
        for window in self._readings.values():
            for entry in window:
                if entry.reading.event_id == event_id:
                    return entry
        return None

    def has_event(self, event_id: str) -> bool:
        return self.find_entry(event_id) is not None

    def reference(self, sensor_id: str) -> HistoryEntry | None:
        for entry in reversed(self._readings.get(sensor_id, ())):
            if entry.clean:
                return entry
        return None

    def last_values(self, sensor_id: str, count: int) -> list[float]:
        if count <= 0:
            return []
        return [e.reading.value for e in list(self._readings.get(sensor_id, ()))[-count:]]

    def soft_streak(self, sensor_id: str, code: str) -> int:
        streak = 0
        for entry in reversed(self._readings.get(sensor_id, ())):
            if code not in entry.codes:
                break
            streak += 1
        return streak

    def recent(self, metric: str, not_before: datetime, not_after: datetime, exclude_sensor: str) -> list[Reading]:
        found: list[Reading] = []
        for sensor_id, window in self._readings.items():
            if sensor_id == exclude_sensor:
                continue
            for entry in reversed(window):
                if not entry.clean or entry.reading.metric != metric or entry.reading.ts > not_after:
                    continue
                if entry.reading.ts >= not_before:
                    found.append(entry.reading)
                break
        return found

    def mark_rolled_back(self, event_id: str, flag: bool = True) -> HistoryEntry | None:
        entry = self.find_entry(event_id)
        if entry is not None:
            entry.rolled_back = flag
        return entry

    def reset(self, sensor_id: str) -> int:
        dropped = len(self._readings.pop(sensor_id, ()))
        self._verdicts.pop(sensor_id, None)
        return dropped

    def record_verdict(self, record: VerdictRecord) -> bool:
        window = self._verdicts.get(record.sensor_id)
        if window is None:
            if len(self._verdicts) >= self.max_sensors:
                return False
            window = self._verdicts[record.sensor_id] = deque(maxlen=self.verdict_window)
        window.append(record)
        entry = self.find_entry(record.event_id)
        if entry is not None:
            entry.verdict = record.verdict
        return True

    def verdicts(self, sensor_id: str, count: int | None = None) -> list[VerdictRecord]:
        items = list(self._verdicts.get(sensor_id, ()))
        return items if count is None else items[-count:] if count > 0 else []

    def calculate_mean(self, history: list[dict[str, Any]]) -> float | None:
        values = [r.get("value") for r in history if isinstance(r.get("value"), (int, float))]
        return sum(values) / len(values) if values else None

    def calculate_std_dev(self, history: list[dict[str, Any]]) -> float | None:
        values = [r.get("value") for r in history if isinstance(r.get("value"), (int, float))]
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        return math.sqrt(sum((x - mean) ** 2 for x in values) / (len(values) - 1))

    def get_latest_value(self, history: list[dict[str, Any]]) -> float | None:
        if not history:
            return None
        value = history[-1].get("value")
        return float(value) if isinstance(value, (int, float)) else None

    def calculate_delta(self, current_value: float, history: list[dict[str, Any]]) -> float:
        previous = self.get_latest_value(history)
        return 0.0 if previous is None else abs(current_value - previous)

    def is_sensor_frozen(self, history: list[dict[str, Any]], count_threshold: int = 5) -> bool:
        if len(history) < count_threshold:
            return False
        recent = [r.get("value") for r in history[-count_threshold:]]
        return len(set(recent)) == 1 and recent[0] is not None