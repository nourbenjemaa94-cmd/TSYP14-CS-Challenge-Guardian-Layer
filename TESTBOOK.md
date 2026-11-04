# Guardian Verification Testbook

This testbook describes the tests currently present in the repository. The
historical suite under `guardian/tests/legacy/` is intentionally excluded from
collection; useful cases have been ported to the current API tests below.

## Test matrix

| Path | Scope | Coverage |
|---|---|---|
| `guardian/tests/unit/security/test_security_gate.py` | Security unit tests | HMAC admission, source and operation policy, replay, freshness, outbound signatures |
| `guardian/tests/unit/security/test_rate_limit.py` | Security unit tests | Rate limits and oversized admissions |
| `guardian/tests/unit/contract/` | Contract unit tests | Profiles, registry selection, mapper, unit conversion, AI proposals |
| `guardian/tests/test_core_history_composition.py` | Core composition | Shared history across anomaly, trust and containment components |
| `guardian/tests/test_containment_pipeline.py` | Core orchestration | Containment request, acknowledgement, failure and idempotency states |
| `guardian/tests/test_main_security.py` | Signed REST/HTTP | FastAPI `TestClient`: missing/altered/wrong signatures, source, time, replay, rate and body limits |
| `guardian/tests/test_verdict_query.py` | Signed Brain HTTP | Verdict persistence, signed request validation, signed response and unknown event |
| `guardian/tests/test_communication_adapters.py` | Communication adapters | Simulated Paho client, TLS/mTLS, reconnect/stop, bounded async handler and REST adapter |
| `guardian/tests/test_brain_output.py` | HTTP output | `httpx.MockTransport` 2xx, 500, timeout, DNS failure, signing and no duplicate send |
| `guardian/tests/test_config.py` | Configuration | YAML/env precedence, MQTT TLS paths, invalid ports and missing keys |
| `guardian/tests/test_readiness.py` | Readiness | Missing keys, invalid configuration, broker failure and complete readiness |
| `guardian/tests/test_timeline.py` | Audit timeline | WebSocket causal order, correlation and safe public fields |
| `guardian/tests/test_c13_timeline_access.py` | C13 access control | Production/demo refusal, local loopback allowance and disabled refusal |
| `guardian/tests/test_docker_compose.py` | Compose contract | Environment file, service targets, healthcheck and mock wiring |

## Requirement R3 checks

The current timeline tests verify that accepted and rejected signed telemetry
preserves one `event_id` across audit stages, rejection occurs before Core
processing, and public timeline events do not disclose signatures or secrets.
The timeline buffer is intentionally in memory and is not durable evidence.

## Running locally

From the repository root:

```bash
cd guardian
python -m pytest -q
python -m pytest --cov=src/guardian --cov-report=term-missing tests
python -m ruff check src tests
PYTHONPATH=src python -m uvicorn guardian.main:app --host 0.0.0.0 --port 8000 --reload
```

On PowerShell, use `$env:PYTHONPATH = "src"` before the Uvicorn command.
`uvicorn src.guardian.main:app` is not supported: `src` is the source root,
not part of the import package name. Tests under `tests/legacy` remain
excluded by `guardian/pytest.ini`.
