# Guardian Verification Testbook (Requirement R3 & Security)

This testbook outlines the test suite and validation scenarios for **Guardian (Layer 2)**.

---

## 1. Test Suite Structure

| Directory | Scope | Key Focus |
|---|---|---|
| `guardian/tests/test_timeline.py` | Requirement R3 Validation | End-to-end WebSocket causal sequence verification (`fake_flood` and legitimate data) |
| `guardian/tests/unit/test_history.py` | Unit Test (Member 3+4) | Sliding window, rolling average, delta rate of change |
| `guardian/tests/unit/test_anomaly_detector.py` | Unit Test (Member 3+4) | Spike detection, physical bounds, flatline / frozen sensors |
| `guardian/tests/unit/test_trust_assessor.py` | Unit Test (Member 3+4) | Trust scoring, verdict generation, downgrade rules |
| `guardian/tests/unit/test_containment.py` | Unit Test (Member 3+4) | Isolation, quarantine, and allow policy matrices |
| `guardian/tests/unit/test_event_store.py` | Unit Test (Member 4+3) | Historical store persistence and lookup |
| `guardian/tests/unit/test_security.py` | Unit Test (Member 2+5) | Token validation, replay attack detection, freshness check |
| `guardian/tests/integration/test_pipeline_integration.py` | Integration (All Members) | End-to-end telemetry pipeline from raw sensor to Brain output |
| `guardian/tests/scenarios/test_attack_scenarios.py` | Cyber Attack Scenarios | Fake flood attack, data poisoning, replay storm |

---

## 2. Requirement R3: Real-time Causal Timeline Audit

### Verification Criteria
1. **WebSocket Connectivity**: Clients connect without authentication hurdles to `/ws/timeline`.
2. **Causal Ordering**: Every telemetry event must generate strictly ordered messages:
   - Stage 1: `READING_RECEIVED`
   - Stage 2: `GUARDIAN_VERDICT`
   - Stage 3: `ISOLATED` (Attack blocked) OR `SENT_TO_BRAIN` (Safe data forwarded)
3. **Correlation Integrity**: The `event_id` must remain identical across all 3 audit stages.
4. **Unit Normalization**: Verify that raw sensor inputs (e.g., `3.8 m`) are accurately converted to canonical units (`380 cm`).

---

## 3. How to Run the Tests

```bash
cd triplet-07/guardian

# Run all test suites
pytest -v

# Run R3 Timeline tests specifically
pytest tests/test_timeline.py -v

# Run with test coverage
pytest --cov=src/guardian --cov-report=term-missing tests/
```
