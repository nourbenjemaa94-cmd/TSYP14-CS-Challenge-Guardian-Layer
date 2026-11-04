# Guardian Interface Specifications

## 1. REST Endpoints

### Verification and supported local command

The supported local test and server commands are documented in the repository
[`TESTBOOK.md`](../TESTBOOK.md). Run them from `guardian/`; the application is
imported as `guardian.main:app` with `PYTHONPATH=src`. The paths under
`tests/legacy` are excluded and are not part of the current interface contract.

### MQTT ingress acknowledgement policy

MQTT TLS is enabled by default and validates the broker certificate using the
system CA store or the configured `ca_cert`; mTLS is enabled only when both
client certificate and private key are configured. For QoS 1/2, Paho sends its
protocol acknowledgement after the `on_message` callback returns. Guardian
therefore uses a bounded local queue: `QUEUED` means that the delivery was
accepted by that queue, not that the Core completed processing. A full queue,
an invalid message, or a pipeline rejection is logged/audited as a terminal
local rejection for that delivery; Guardian does not claim `DELIVERED` and
cannot request a protocol-level NACK from the Paho callback.

### `POST /api/v1/telemetry`
Ingests raw telemetry messages from Digital Twin or physical sensor gateways.

**Request Headers:**
- `Content-Type: application/json`
- `Authorization: Bearer <token>` (Optional if token included in body)

**Request Body:**
```json
{
  "event_id": "EVT-ATTACK-FAKE-FLOOD-01",
  "sensor_id": "S01",
  "levelOfWater": 3.8,
  "unit": "m",
  "token": "valid_token",
  "timestamp": "2026-10-20T10:00:00Z"
}
```

## 3. Mapping profiles

Mapping profiles are validated and versioned records stored under
`GUARDIAN_PROFILE_DIR`. Selection requires the authenticated Twin identity,
the envelope event type, and (when supplied) `schema_id`; only `ACTIVE`
records are usable. `PENDING` proposals, including `AIMapper` proposals, are
never activated automatically and never invoke an LLM on the live measurement
path. No compatible or uniquely selectable profile returns the public
`UNKNOWN_SCHEMA` error; the mapper does not invent units, timestamps, or
identities.

**Responses:**
- `200 OK`: Telemetry processed. Response includes canonical message, `trust_verdict`, and `containment_action`.
- `401 Unauthorized`: Token missing or invalid.
- `422 Unprocessable Entity`: Schema validation failure.

---

### `POST /v1/verdicts/query`
Queries verdicts already persisted by the Guardian Core. This is the Brain
request path from the triplet contract; it is not a substitute for telemetry
ingestion.

The request is a signed `verdict_request` envelope from `source.layer=brain`
and must be admitted with the `request_verdict` operation:

```json
{
  "schema_version": "1.0",
  "event_id": "evt-verdict-request",
  "seq": 1,
  "timestamp": "2026-10-20T10:00:00Z",
  "source": {"layer": "brain", "device_id": "planner"},
  "zone_id": "PORT",
  "type": "verdict_request",
  "payload": {"event_ids": ["EVT-ATTACK-FAKE-FLOOD-01"]},
  "signature": "<HMAC made with the Brain key>"
}
```

For known event IDs, Guardian returns a `trust_verdict` envelope signed at
runtime with `SecurityGate.sign_outbound` and the Guardian HMAC key. A missing
or invalid request signature is rejected (`401`/`403` as applicable), and an
unknown event ID returns `404 VERDICT_NOT_FOUND`. The response signature must
be verified by Brain; it is never a fixed or hard-coded value.

---

### `GET /health`
Process liveness probe. It only confirms that the Guardian process responds;
it does not claim that secrets, adapters, or the processing pipeline are ready.

**Response (200 OK):**
```json
{
  "status": "ALIVE",
  "service": "guardian-gateway"
}
```

### `GET /ready`
Readiness probe for the complete production composition. It returns `200`
only when the HMAC configuration, real `SecurityGate`, `GenericMapper`,
output adapter, orchestration worker, required Twin adapter, and (when MQTT is
configured) its broker connection are ready. Missing keys, invalid
configuration, an unavailable broker, or a stopped worker return `503
NOT_READY`; `/health` remains available for liveness during those failures.

---

## 2. WebSocket Endpoints

### `WS /ws/timeline`
Live, in-memory audit stream designed for jury inspection, monitoring
dashboards, and real-time verification (Requirement R3). The buffer is not
persistent evidence and is lost on process restart.

Exposure is disabled by default, including in the normal Docker Compose
deployment. Set `GUARDIAN_TIMELINE_MODE=local` only for loopback/test tooling.
`GUARDIAN_ENV=production` always rejects this unauthenticated endpoint,
regardless of `GUARDIAN_TIMELINE_MODE`; `demo` is also restricted to loopback
until an authenticated external demonstration policy is approved. Other modes
close the WebSocket with policy violation (`1008`). Events contain a whitelist
of public correlation and decision fields; raw signatures, tokens, credentials,
and unknown payload fields are never sent.

**Connection:** `ws://<host>:<port>/ws/timeline`

**Broadcast Event Format:**
```json
{
  "timestamp": "2026-10-20T10:00:00.123456Z",
  "event_id": "EVT-ATTACK-FAKE-FLOOD-01",
  "layer": "GUARDIAN_CORE",
  "stage": "GUARDIAN_VERDICT",
  "sensor_id": "S01",
  "verdict": "UNTRUSTED",
  "reason": "ANOMALY_DETECTED",
  "action": "ISOLATE",
  "anomaly_flags": ["SUDDEN_SPIKE_DETECTED", "PHYSICAL_INCOHERENCE"]
}
```
