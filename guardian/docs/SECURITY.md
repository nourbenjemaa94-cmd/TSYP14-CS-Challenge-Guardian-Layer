# Guardian Security Model & Threat Matrix

## 1. Threat Model & Mitigations

| Threat | Attack Vector | Detection Subsystem | Containment Mitigation |
|---|---|---|---|
| **Spoofed Flood Spike** | Injected telemetry claiming 3.8m water rise | `core/anomaly_detector.py` | `ISOLATE` - Blocked at gateway; never reaches Brain |
| **Replay Attack** | Re-sending captured telemetry packets | `security/replay_protection.py` & `security/freshness.py` | `SECURITY_REJECTED` - Dropped immediately |
| **Unauthorized Emitter** | Rogue sensor emitting unauthenticated data | `security/authentication.py` | `401 Unauthorized` & Audit logged |
| **Frozen / Dead Sensor** | Damaged gauge sending constant value | `core/history.py` | `SUSPICIOUS` / `QUARANTINE` |
| **Unit Confusion Attack** | Emitter sending meters when centimeters expected | `adapters/contract/unit_converter.py` | Automatic canonical normalization |

---

## 2. Zero-Trust Verification Pipeline

Every incoming packet passes through strict non-bypassable stages:

1. **Authentication Barrier**: Token authenticity and signature integrity checked.
2. **Freshness & Nonce Verification**: Messages outside timestamp window (300s) rejected.
3. **Canonical Normalization**: Standardizes vendor units to prevent unit confusion bugs.
4. **Physical Baseline Comparison**: Evaluates values against historical moving averages and rate-of-change limits.
5. **Containment Enforcement**: Malicious data is quarantined or blocked with zero leakage to City Brain.
6. **Audit Immutability**: All decisions broadcast to `/ws/timeline` with guaranteed `event_id` correlation.

