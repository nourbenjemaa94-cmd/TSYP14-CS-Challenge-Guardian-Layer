# triplet-07 · Guardian Layer

Guardian layer of **Triplet 07** (Digital Twin ↔ Guardian ↔ City Brain) for the TSYP14 "City Brain Convergence" challenge.
The Guardian watches the same sensor stream as the City Brain and asks one question about every reading:
**"Is this sensor telling the truth?"** It issues a trust verdict before the Brain acts, and contains confirmed problems
(isolate a sensor, quarantine a device, roll back a falsified reading).

## Team and responsibilities

- **Member 1 (Mohamed Amine Hayouni)**: Communication & Contract Adapters (`adapters/`, `contracts/`)
- **Member 2 (Nour Ben Jemaa)**: Contract Adapters & Security (`adapters/`, `security/`)
- **Member 3 (Rayen Saidi)**: Core Engine & Audit Store (`core/`, `audit/`)
- **Member 4 (Ghaith Mnasri)**: Core Security & Verification Engine (`core/`, `audit/`, `orchestration/`)
- **Member 5 (Nour Zghonda)**: Security, Freshness & Replay Protection (`security/`)
- **Member 6 (Sarra Mtir)**: Contracts & Ingestion Adapters (`contracts/`, `adapters/`)

## Architecture

```
[ Twin / sensors ]
        |  REST / MQTT
        v
 Communication adapter -> Security (auth, freshness, replay) -> Contract adapter (canonical model)
        |
        v
 Guardian core:  history -> anomaly_detector -> trust_assessor -> containment
        |
        v
 Audit (logger, event store, live timeline)  ->  [ City Brain ]
```

Detection, trust scoring and containment are separate modules. The core never talks to a partner: transport lives in
`adapters/`, message checks in `security/`, logging in `audit/`, and `orchestration/pipeline.py` wires them together.

## Repository layout

```
src/guardian/
├── main.py
├── config.py
├── adapters/        communication/ (REST, MQTT)  contract/ (mapper, units)
├── contracts/       events, verdicts, commands
├── security/        authentication, authorization, validation, freshness, replay protection
├── core/            history.py  anomaly_detector.py  trust_assessor.py  containment.py
├── audit/           logger.py  event_store.py  timeline.py
└── orchestration/   pipeline.py
tests/               unit, integration, scenarios
INTERFACE.md         interface card (messages and examples)
Architecrute.md      full architecture tree
config.example.yaml  configurable partner addresses and thresholds
```

## Run

```bash
pip install -r requirements.txt
pytest -v
uvicorn src.guardian.main:app --host 0.0.0.0 --port 8000 --reload
```

The core uses only the Python standard library, so it adds nothing to `requirements.txt`.

## Core (`src/guardian/core/`)

There is no `__init__.py` in `core/` (namespace package, as in the architecture tree). Import with
`from guardian.core.history import HistoryTracker`, or `from core.history import ...` when `src/guardian` is on `sys.path` as in `main.py`.

| Module | Responsibility | Main entry points |
|---|---|---|
| `history.py` | Bounded per-sensor readings and per-device verdicts; reading validation | `HistoryTracker`, `Reading.from_message` |
| `anomaly_detector.py` | Lists what is wrong with one reading | `AnomalyDetector.analyze` / `detect` |
| `trust_assessor.py` | Turns findings and device history into a verdict | `TrustAssessor.evaluate` / `assess` |
| `containment.py` | Isolates, quarantines, rolls back, releases; reports what changed | `ContainmentEngine.contain` |

### Quick use

```python
from guardian.core.history import HistoryTracker
from guardian.core.anomaly_detector import AnomalyDetector
from guardian.core.trust_assessor import TrustAssessor
from guardian.core.containment import ContainmentEngine

history = HistoryTracker()                          # ONE shared instance
detector = AnomalyDetector(history=history)
assessor = TrustAssessor(history=history)
containment = ContainmentEngine(history=history)    # port=... to call the Twin

reading = {"event_id": "E1", "sensor_id": "S01", "metric": "water_level",
           "value": 180, "unit": "cm", "timestamp": "2026-10-20T10:00:05Z"}

detection = detector.analyze(reading)
verdict = assessor.evaluate(detection)
report = containment.contain(verdict)
```

The calls `pipeline.py` already makes still work: `detector.detect(msg, history)`, `assessor.assess(msg, flags)`,
`containment.evaluate_action(flags, verdict)`. They do not execute containment; `contain()` does.

### Canonical reading

| Field | Rule |
|---|---|
| `sensor_id`, `metric` | 1-64 chars of letters, digits, `_ . : -` |
| `value` | finite number (not bool) |
| `timestamp` | ISO 8601 (naive = UTC) |
| `event_id` | optional, max 128 chars |
| `unit` | optional, max 16 chars |

A malformed reading never raises in `analyze`: it becomes a hard finding such as `INVALID_SENSOR_ID`.

### Detection

| Check | Code | Severity |
|---|---|---|
| Out of physical range | `PHYSICAL_BOUNDS_VIOLATION` | hard |
| Unit differs from expected | `UNIT_MISMATCH` | hard |
| Change faster than `hard_rate_factor` x limit | `SUDDEN_SPIKE_DETECTED` | hard |
| Change faster than limit | `SUSPECTED_SPIKE` | soft |
| N identical readings | `SENSOR_FROZEN_STAGNANT` | soft |
| High reading not confirmed by correlated sensors | `PHYSICAL_INCOHERENCE` | soft |
| Timestamp older than previous reading | `TIMESTAMP_REGRESSION` | soft |
| Metric without configured limits | `UNKNOWN_METRIC` | soft |
| Same `event_id` seen again | `DUPLICATE_EVENT` | soft |
| Soft finding on N consecutive readings | `PERSISTENT_ANOMALY` | hard |
| Invalid fields, sensor cap reached | `INVALID_*`, `MALFORMED_MESSAGE`, `MISSING_OR_INVALID_VALUE`, `TOO_MANY_SENSORS` | hard |

False-alarm handling:
- Soft findings must persist on `persistence_readings` (default 3) consecutive readings before they escalate.
- A jump confirmed by correlated sensors (flood camera or emergency calls within `window_sec`) is not flagged.
- The reference value is the last clean reading, so a spoofed value never becomes the baseline.
- Rolled-back and flagged readings are excluded from the baseline.

### Trust verdict

- Any hard finding gives `UNTRUSTED`.
- Otherwise `score = 1 - sum(penalties)`: below 0.4 is `UNTRUSTED`, below 0.7 is `SUSPICIOUS`, else `TRUSTED`.
- After a non-trusted verdict a device stays `SUSPICIOUS` (`DEVICE_RECOVERING`) until `recovery_clean_readings` clean verdicts.
- `confidence` is a heuristic strength of evidence in [0, 1], not a calibrated probability.

```json
{"event_id": "E1", "sensor_id": "S01", "verdict": "UNTRUSTED", "confidence": 0.8,
 "reason_code": "SUDDEN_SPIKE_DETECTED", "reason": "ANOMALY_DETECTED", "score": 0.2,
 "assessment_id": "assess-000006", "policy_version": "1.0",
 "timestamp": "2026-10-20T10:00:05+00:00",
 "evidence": [{"code": "SUDDEN_SPIKE_DETECTED", "severity": "hard", "detail": "40.0 -> 180.0 is 140.0/s, limit 15.0/s"}]}
```

### Containment

| Verdict | Reading action | Device state change (defaults) |
|---|---|---|
| `TRUSTED` | `ALLOW` | quarantine lifted after 5 clean verdicts |
| `SUSPICIOUS` | `QUARANTINE` | quarantined after 2 consecutive |
| `UNTRUSTED` | `ISOLATE` | isolated at once, reading rolled back |

- Device states: `ACTIVE`, `QUARANTINED`, `ISOLATED`. Isolation is lifted only by `release()`.
- Action lifecycle: `REQUESTED -> ACCEPTED -> APPLIED`, or `FAILED`. `remote_confirmed` is true only after the Twin confirmed.
- If the Twin rejects an isolation, the device stays blocked locally and the next `UNTRUSTED` verdict retries.
- Rollback flags the reading; the original value stays in history. `restore_reading()` reverses it (local only).
- Malformed or duplicate messages never change a device state, so garbage sent in a device's name cannot isolate it.
- `contain()` is idempotent per `assessment_id`; every action carries an idempotency key.
- Quarantine and release are Guardian-local (the Twin tool catalogue has no such tools).

Twin calls go through a port supplied by `adapters/`:

```python
class ContainmentPort(Protocol):
    def isolate_device(self, device_id: str, idem_key: str) -> PortResult: ...
    def rollback_reading(self, event_id: str, idem_key: str) -> PortResult: ...
```

### Configuration

Each config is a dataclass with `from_mapping()` for the YAML sections:

| Class | Section | Main keys |
|---|---|---|
| `DetectorConfig` | `detection:` | `persistence_readings`, `hard_rate_factor`, per-metric `min_value`, `max_value`, `max_rate_per_sec`, `stuck_count`, `unit` |
| `TrustConfig` | `trust:` | `isolate_threshold`, `quarantine_threshold`, `recovery_clean_readings` |
| `ContainmentConfig` | `containment:` | `isolate_after_untrusted`, `quarantine_after_suspicious`, `release_quarantine_after_trusted`, `rollback_untrusted_readings` |

Unknown keys are ignored. Limits for metrics other than `water_level` are placeholders to tune by simulation.

### Determinism and testing

Detection and trust use only message timestamps, never the wall clock. `ContainmentEngine(clock=...)` takes a fake clock and
`port=...` a mock Twin, so a scenario replays identically from one command.

### Integration notes

- Create one `HistoryTracker` in `main.py` and pass it to the detector, assessor and containment engine.
- In `pipeline.py` use `assessor.evaluate(detection)` and call `containment.contain(verdict)` to execute containment.
- Do not commit `__pycache__/`.

### Known limitations

- Correlation is one-directional: a high water level needs support, but a flood camera alone is not checked against water level.
- Authentication, replay and freshness belong to `security/`; the core only adds a duplicate `event_id` check.
- State is in memory: a restart clears history and device states.