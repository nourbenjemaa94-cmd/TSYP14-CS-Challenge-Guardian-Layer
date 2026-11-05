# Guardian Interface Specifications

## 1. REST Endpoints

### Verification and supported local command

The supported local test and server commands are documented in the repository
[`TESTBOOK.md`](../TESTBOOK.md). Run them from `guardian/`; the application is
imported as `guardian.main:app` with `PYTHONPATH=src`.

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

**Request Body:** a signed envelope. HMAC-SHA256 over the canonical JSON, field `signature`, key `GUARDIAN_HMAC_KEY_TWIN`.

```json
{
  "schema_version": "1.0",
  "schema_id": "twin-canonical-v1",
  "event_id": "evt-normal-1",
  "seq": 1,
  "timestamp": "2026-11-05T06:57:38.000Z",
  "source": {"layer": "twin", "device_id": "S01"},
  "zone_id": "PORT",
  "type": "sensor_reading",
  "payload": {"metric": "water_level", "value": 180, "unit": "cm"},
  "signature": "<HMAC-SHA256>"
}
```

## 3. Mapping profiles

Mapping profiles are validated and versioned records stored under
`GUARDIAN_PROFILE_DIR`. Selection requires the authenticated Twin identity,
the envelope event type, and (when supplied) `schema_id`; `ACTIVE` and
`PROBATION` records are usable. `PENDING` proposals never invoke an LLM on
the live measurement path. An unknown shape is buffered and returns
`202 ONBOARDING_PENDING` with a `fingerprint` (replacing a bare `UNKNOWN_SCHEMA`
when the onboarding manager is attached). After automatic gates pass, the
profile is `PROBATION` and is promoted to `ACTIVE` after
`GUARDIAN_PROBATION_MESSAGES` clean maps.

**Responses:**
- `200 OK`: Telemetry processed. Response includes canonical message, `trust_verdict`, and `containment_action`.
- `202 Accepted`: `ONBOARDING_PENDING` — unknown authenticated shape is being mapped.
- `401 Unauthorized`: `SIGNATURE_MISSING`, `SIGNATURE_INVALID`, or `UNKNOWN_SENDER`.
- `409 Conflict`: `REPLAY`.
- `422 Unprocessable Entity`: `SCHEMA_INVALID`, `STALE_TIMESTAMP`, `FUTURE_TIMESTAMP`, `UNKNOWN_SCHEMA`, or `UNMAPPABLE_SCHEMA`.
- `429 Too Many Requests`: `RATE_LIMITED`.

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
  "service": "guardian-gateway",
  "triplet": "Triplet 07",
  "llm": "reachable"
}
```

`llm` is `disabled`, `reachable`, or `unreachable`.

### `GET /api/v1/verdicts/{event_id}`
Unauthenticated read of one already-signed persisted verdict. `404 VERDICT_NOT_FOUND` if missing.

### `POST /api/v1/profiles/{fingerprint}/reset`
Signed `reset_profile` operation. Only `source.layer=guardian` may call it. Removes an `UNMAPPABLE` record so the shape can be tried again.

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
