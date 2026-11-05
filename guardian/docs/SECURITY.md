# Guardian Security Model & Threat Matrix

## 1. Threat Model & Mitigations

| Threat | Attack Vector | Detection Subsystem | Containment Mitigation |
|---|---|---|---|
| **Spoofed Flood Spike** | Injected telemetry claiming 3.8m water rise | `core/anomaly_detector.py` | `ISOLATE` - Blocked at gateway; never reaches Brain |
| **Replay Attack** | Re-sending captured telemetry packets | `security/gate.py` (`ReplayProtector`) and timestamp checks in `security/freshness.py` helpers | `REPLAY` / `STALE_TIMESTAMP` — dropped before Core |
| **Unauthorized Emitter** | Rogue sensor emitting unauthenticated data | `security/authentication.py` | `SIGNATURE_MISSING` / `SIGNATURE_INVALID` / `UNKNOWN_SENDER` |
| **Frozen / Dead Sensor** | Damaged gauge sending constant value | `core/history.py` | `SUSPICIOUS` / `QUARANTINE` |
| **Unit Confusion Attack** | Emitter sending meters when centimeters expected | `adapters/contract/unit_converter.py` | Automatic canonical normalization |

---

## 2. Zero-Trust Verification Pipeline

Every incoming packet passes through strict non-bypassable stages:

1. **Authentication Barrier**: HMAC-SHA256 signature over the canonical envelope (`security/authentication.py`).
2. **Freshness & Replay**: `admit` rate-limits; `accept` rejects `STALE_TIMESTAMP` / `FUTURE_TIMESTAMP` / `REPLAY`.
3. **Canonical Normalization**: Standardizes vendor units to prevent unit confusion bugs.
4. **Physical Baseline Comparison**: Evaluates values against historical moving averages and rate-of-change limits.
5. **Containment Enforcement**: Malicious data is quarantined or blocked with zero leakage to City Brain.
6. **Audit Immutability**: All decisions broadcast to `/ws/timeline` with guaranteed `event_id` correlation.

Public security reason codes: `MESSAGE_TOO_LARGE`, `MALFORMED_JSON`, `SCHEMA_INVALID`, `SIGNATURE_MISSING`, `SIGNATURE_INVALID`, `UNKNOWN_SENDER`, `FORBIDDEN`, `RATE_LIMITED`, `SOURCE_MISMATCH`, `STALE_TIMESTAMP`, `FUTURE_TIMESTAMP`, `REPLAY`, `FORMAT_MISMATCH`.

