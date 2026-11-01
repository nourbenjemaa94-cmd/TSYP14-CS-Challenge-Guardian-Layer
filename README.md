# Core

This folder is the brain of the Guardian. For every sensor reading it decides if the reading can be trusted,
and if not, what to do about it. It does not receive messages and it does not send them: that is the job of
`adapters/`, `security/` and `audit/`. The core only works on readings that were already checked and converted.

## Files

| File | What it does |
|---|---|
| `history.py` | Keeps the last readings of each sensor and the last verdicts of each device. Also checks that a reading is well formed. |
| `anomaly_detector.py` | Looks at one reading and its history and lists the problems found. |
| `trust_assessor.py` | Takes those problems and gives a verdict: `TRUSTED`, `SUSPICIOUS` or `UNTRUSTED`, with a reason and a confidence. |
| `containment.py` | Applies the verdict: isolate a sensor, quarantine it, roll back a false reading, or release it later. |

The order is always the same:

```
reading -> anomaly_detector -> trust_assessor -> containment
                 \________________ history ________________/
```

The three classes share one `HistoryTracker`, so create it once and give it to each of them.

## Example

```python
from core.history import HistoryTracker
from core.anomaly_detector import AnomalyDetector
from core.trust_assessor import TrustAssessor
from core.containment import ContainmentEngine

history = HistoryTracker()
detector = AnomalyDetector(history=history)
assessor = TrustAssessor(history=history)
containment = ContainmentEngine(history=history)

reading = {
    "event_id": "E1",
    "sensor_id": "S01",
    "metric": "water_level",
    "value": 180,
    "unit": "cm",
    "timestamp": "2026-10-20T10:00:05Z",
}

detection = detector.analyze(reading)
verdict = assessor.evaluate(detection)
report = containment.contain(verdict)

print(verdict.to_dict())
print(report.to_dict())
```

The old calls used by `pipeline.py` still work: `detector.detect(msg, history)`, `assessor.assess(msg, flags)`
and `containment.evaluate_action(flags, verdict)`. They only give a decision. To really isolate or quarantine,
call `containment.contain(verdict)`.

## Reading format

| Field | Rule |
|---|---|
| `sensor_id`, `metric` | 1 to 64 characters: letters, digits, `_`, `.`, `:`, `-` |
| `value` | a normal number (not NaN, not a boolean) |
| `timestamp` | ISO 8601 date, for example `2026-10-20T10:00:05Z` |
| `event_id` | optional, 128 characters max |
| `unit` | optional, 16 characters max |

A bad reading never crashes the detector. It is returned as a problem such as `INVALID_SENSOR_ID`.

## What the detector looks for

| Problem | Code | Strength |
|---|---|---|
| Value outside the possible range | `PHYSICAL_BOUNDS_VIOLATION` | hard |
| Wrong unit (for example `m` instead of `cm`) | `UNIT_MISMATCH` | hard |
| Value jumps very fast | `SUDDEN_SPIKE_DETECTED` | hard |
| Value jumps fast | `SUSPECTED_SPIKE` | soft |
| Same value many times in a row | `SENSOR_FROZEN_STAGNANT` | soft |
| High water level that other sensors do not confirm | `PHYSICAL_INCOHERENCE` | soft |
| Timestamp older than the previous reading | `TIMESTAMP_REGRESSION` | soft |
| Metric with no configured limits | `UNKNOWN_METRIC` | soft |
| Same `event_id` received twice | `DUPLICATE_EVENT` | soft |
| A soft problem repeated several times | `PERSISTENT_ANOMALY` | hard |
| Malformed reading | `MALFORMED_MESSAGE`, `INVALID_*`, `MISSING_OR_INVALID_VALUE`, `TOO_MANY_SENSORS` | hard |

A hard problem makes the reading `UNTRUSTED` immediately. A soft problem only counts as a warning.

To avoid false alarms:
- a soft problem must happen 3 readings in a row (`persistence_readings`) before it becomes hard;
- a fast rise is accepted if other sensors confirm it (flood camera or emergency calls);
- each new reading is compared with the last clean one, so a fake value never becomes the normal value;
- readings that were flagged or rolled back are not used as a reference.

## Verdict

- A hard problem gives `UNTRUSTED`.
- Otherwise every problem removes points from a score that starts at 1. Under 0.4 is `UNTRUSTED`, under 0.7 is `SUSPICIOUS`, otherwise `TRUSTED`.
- After a bad verdict the sensor stays `SUSPICIOUS` until it sends 3 clean readings in a row.
- `confidence` goes from 0 to 1. It shows how strong the evidence is, it is not an exact probability.

Example of `verdict.to_dict()`:

```json
{
  "event_id": "E1",
  "sensor_id": "S01",
  "verdict": "UNTRUSTED",
  "confidence": 0.8,
  "reason_code": "SUDDEN_SPIKE_DETECTED",
  "reason": "ANOMALY_DETECTED",
  "score": 0.2,
  "assessment_id": "assess-000006",
  "policy_version": "1.0",
  "timestamp": "2026-10-20T10:00:05+00:00",
  "evidence": [
    {"code": "SUDDEN_SPIKE_DETECTED", "severity": "hard", "detail": "40.0 -> 180.0 is 140.0/s, limit 15.0/s"}
  ]
}
```

## Containment

| Verdict | What happens to the reading | What happens to the sensor |
|---|---|---|
| `TRUSTED` | `ALLOW` | a quarantine is lifted after 5 clean readings |
| `SUSPICIOUS` | `QUARANTINE` | quarantined after 2 suspicious readings in a row |
| `UNTRUSTED` | `ISOLATE` | isolated right away, and the false reading is rolled back |

- A sensor is `ACTIVE`, `QUARANTINED` or `ISOLATED`. An isolated sensor stays isolated until `release()` is called.
- Every action returns what it changed, with a status: `APPLIED`, `ACCEPTED` (not confirmed yet), `FAILED` or `NOOP`.
- If the Twin refuses an isolation, the sensor is still blocked on our side and we try again on the next bad reading.
- A rollback does not delete anything. The reading is only marked, and `restore_reading()` can undo it.
- A malformed or duplicate message never isolates a sensor, so nobody can isolate a sensor by sending garbage with its name.
- Calling `contain()` twice with the same verdict does the work only once.
- Quarantine and release are done inside the Guardian only, because the Twin has no tool for them.

The calls to the Twin go through a port that `adapters/` provides:

```python
class ContainmentPort(Protocol):
    def isolate_device(self, device_id: str, idem_key: str) -> PortResult: ...
    def rollback_reading(self, event_id: str, idem_key: str) -> PortResult: ...
```

Without a port, everything is done locally and `remote_confirmed` stays `False`.

## Configuration

Nothing is fixed in the code. Each part has a config class with a `from_mapping()` method that reads a section of the yaml file.

| Class | yaml section | Main keys |
|---|---|---|
| `DetectorConfig` | `detection:` | `persistence_readings`, `hard_rate_factor`, and for each metric `min_value`, `max_value`, `max_rate_per_sec`, `stuck_count`, `unit` |
| `TrustConfig` | `trust:` | `isolate_threshold`, `quarantine_threshold`, `recovery_clean_readings` |
| `ContainmentConfig` | `containment:` | `isolate_after_untrusted`, `quarantine_after_suspicious`, `release_quarantine_after_trusted`, `rollback_untrusted_readings` |

Unknown keys are ignored. Only `water_level` has real limits for now; the other metrics use default values to tune later with the simulation.

## Testing

The detector and the assessor only use the timestamps of the readings, never the real clock, so the same input always gives the same result.
`ContainmentEngine(clock=...)` accepts a fake clock and `port=...` accepts a fake Twin.

## To connect in the pipeline

- create one `HistoryTracker` in `main.py` and give it to the three classes;
- in `pipeline.py`, use `assessor.evaluate(detection)` and then `containment.contain(verdict)`.

## Limits

- The water level is checked against the other sensors, but not the other way around.
- Login, freshness and replay checks are done in `security/`. The core only rejects a repeated `event_id`.
- Everything is kept in memory, so a restart clears the history and the sensor states.