# Guardian interface card

Guardian decides whether a message is authentic, allowed, well-formed, fresh, and new. It does not decide whether a sensor reading is true. Partners send a signed envelope. Guardian answers with a small JSON result or, for a verdict or device-status query, with a signed envelope of its own.

An automated agent is just another caller using the `twin` or `brain` identity. It receives the same operation list as that layer. Containment is not an inbound operation. Guardian's replies are enums and reason codes.

## What Guardian receives

| Method and path | Operation | Caller | Envelope `type` |
|---|---|---|---|
| `POST /v1/readings` | `publish_reading` | twin | `sensor_reading` |
| `POST /v1/actuator-states` | `report_actuator_state` | twin | `actuator_state` |
| `POST /v1/command-acks` | `ack_command` | twin | `command_ack` |
| `POST /v1/verdicts/query` | `request_verdict` | brain | `verdict_request` |
| `POST /v1/devices/status` | `get_device_status` | brain | `device_status_request` |
| `POST /v1/decisions` | `report_decision` | brain | `decision` |
| `GET /health` | none | anyone | no body |

`GET /health` is the only unsigned call. It returns `status`, `contract_version`, and `degraded`.

MQTT, when the Twin publishes the stream that way:

| Topic | Direction | Operation |
|---|---|---|
| `city/twin/readings/{device_id}` | Twin to Guardian | `publish_reading` |
| `city/twin/actuators/{device_id}` | Twin to Guardian | `report_actuator_state` |
| `city/twin/acks` | Twin to Guardian | `ack_command` |
| `city/guardian/verdicts` | Guardian to Brain | outbound, signed |
| `city/guardian/commands` | Guardian to Twin | outbound, signed |

MQTT has no reply. A rejected MQTT message is audited and logged.

A successful ingestion returns:

```json
{"status": "accepted", "event_id": "evt-8f2c1a"}
```

`request_verdict` and `get_device_status` return a signed Guardian envelope instead of that acknowledgement.

## Envelope

| Field | Type | Rule |
|---|---|---|
| `schema_version` | string | `MAJOR.MINOR`. Major must equal `GUARDIAN_SCHEMA_MAJOR` (default 1). |
| `event_id` | string | Created by the sender. 1–128 characters from `[A-Za-z0-9._:-]`. Unique per source. Carried unchanged. |
| `seq` | integer ≥ 0 | Monotonic per source (layer + device). The first value may be anything. After that, increase by 1. |
| `timestamp` | string | ISO-8601 UTC, millisecond precision, suffix `Z`. Example: `2026-11-08T12:00:00.000Z`. |
| `source` | object | `{"layer": "twin", "device_id": "S01"}`. `device_id` is optional for non-device senders. `layer` is `twin`, `brain`, or `guardian`. |
| `zone_id` | string, optional | Shared spatial key, 1–128 characters from `[A-Za-z0-9._:-]`. |
| `type` | string | Lowercase message name, such as `sensor_reading`. |
| `payload` | object | Type-specific. Security does not interpret it. |
| `signature` | string | `hmac-sha256:` plus 64 lowercase hex characters. |

Unknown fields are ignored. A different schema major version is refused. `payload` schemas belong to the contracts work.

## How it authenticates

`source.layer` selects the HMAC key: `GUARDIAN_HMAC_KEY_TWIN`, `GUARDIAN_HMAC_KEY_BRAIN`, or `GUARDIAN_HMAC_KEY_GUARDIAN`. The signature is checked on the parsed envelope before any mapping. Mapping cannot change the sender: if the canonical `source.layer` differs from the authenticated layer, Guardian returns `SOURCE_MISMATCH`.

Signing rules, which partners implement exactly:

1. Take the envelope without the `signature` field.
2. Serialise as JSON with keys sorted recursively, no whitespace (separators `,` and `:`), UTF-8, and non-ASCII characters not escaped.
3. Compute HMAC-SHA256 over those bytes with the sender layer's key, encoded as UTF-8. Hex-encode in lowercase. Prefix `hmac-sha256:`.

Integer `1` and float `1.0` are different bytes. The first integration test with each partner should exchange one signed message in each direction.

The examples below were signed with documentation keys, not deployment keys:

- twin: `example-twin-key-do-not-use-0123456789`
- brain: `example-brain-key-do-not-use-012345678`
- guardian: `example-guardian-key-do-not-use-012345`

### sensor_reading

```json
{
  "schema_version": "1.0",
  "event_id": "evt-8f2c1a",
  "seq": 1042,
  "timestamp": "2026-11-08T12:00:00.000Z",
  "source": {"layer": "twin", "device_id": "S01"},
  "zone_id": "PORT",
  "type": "sensor_reading",
  "payload": {"metric": "water_level", "value": 180, "unit": "cm"},
  "signature": "hmac-sha256:bf00ea3676e7d9d52352ab2b9518310d50f77be0ccfca106f98c4bfacb031259"
}
```

### actuator_state

```json
{
  "schema_version": "1.0",
  "event_id": "evt-act-1",
  "seq": 88,
  "timestamp": "2026-11-08T12:00:00.000Z",
  "source": {"layer": "twin", "device_id": "A01"},
  "zone_id": "PORT",
  "type": "actuator_state",
  "payload": {"state": "OPEN", "command_event_id": "evt-cmd-1"},
  "signature": "hmac-sha256:1df4691eafdecf54d14077cf81a4ef4562fd6599178d4a56a35c4134913e6443"
}
```

### command_ack

```json
{
  "schema_version": "1.0",
  "event_id": "evt-ack-1",
  "seq": 89,
  "timestamp": "2026-11-08T12:00:00.000Z",
  "source": {"layer": "twin", "device_id": "A01"},
  "zone_id": "PORT",
  "type": "command_ack",
  "payload": {"command_event_id": "evt-cmd-1", "status": "APPLIED", "reason_code": "OK"},
  "signature": "hmac-sha256:7c737ffabd50313563f1bd17d0b36520f3cbf33e94f57fc8433a8ffb881cb29c"
}
```

### verdict_request

```json
{
  "schema_version": "1.0",
  "event_id": "evt-query-1",
  "seq": 12,
  "timestamp": "2026-11-08T12:00:00.000Z",
  "source": {"layer": "brain", "device_id": "planner"},
  "zone_id": "PORT",
  "type": "verdict_request",
  "payload": {"event_ids": ["evt-8f2c1a"]},
  "signature": "hmac-sha256:9e982b27c347fe912ecfdfdfeaee4fb3c2634f14ed32aa889d0f78cc34a9d49c"
}
```

### device_status_request

```json
{
  "schema_version": "1.0",
  "event_id": "evt-status-req",
  "seq": 13,
  "timestamp": "2026-11-08T12:00:00.000Z",
  "source": {"layer": "brain"},
  "zone_id": "PORT",
  "type": "device_status_request",
  "payload": {"device_id": "S01"},
  "signature": "hmac-sha256:b2e9a2832792c9030e324016d72dff32c7497870a908c8d57a6b77324f91f3b6"
}
```

### decision

```json
{
  "schema_version": "1.0",
  "event_id": "evt-decision-1",
  "seq": 14,
  "timestamp": "2026-11-08T12:00:00.000Z",
  "source": {"layer": "brain"},
  "zone_id": "PORT",
  "type": "decision",
  "payload": {"decision": "HOLD", "reason_code": "NONE", "event_ids": ["evt-8f2c1a"]},
  "signature": "hmac-sha256:5dd68f5232e66d1b17df351676da89c7f5cea2845e3b3e73ab6072b9807b92e3"
}
```

### trust_verdict

```json
{
  "schema_version": "1.0",
  "event_id": "evt-verdict-1",
  "seq": 0,
  "timestamp": "2026-11-08T12:00:00.000Z",
  "source": {"layer": "guardian"},
  "zone_id": "PORT",
  "type": "trust_verdict",
  "payload": {"event_ids": ["evt-8f2c1a"], "verdict": "INSUFFICIENT_DATA", "reason_code": "CORE_STUB"},
  "signature": "hmac-sha256:574c25518d0942428c2bbf8a7b694a764416329851782ca54bee0413399b5547"
}
```

### device_status

```json
{
  "schema_version": "1.0",
  "event_id": "evt-status-1",
  "seq": 1,
  "timestamp": "2026-11-08T12:00:00.000Z",
  "source": {"layer": "guardian"},
  "zone_id": "PORT",
  "type": "device_status",
  "payload": {"device_id": "S01", "status": "UNKNOWN", "reason_code": "CORE_STUB"},
  "signature": "hmac-sha256:8c9df3a9ea69344f16b26bd96dac8423074b5f4a17d6ed2695020f821640afb7"
}
```

### isolation_command

```json
{
  "schema_version": "1.0",
  "event_id": "evt-iso-1",
  "seq": 2,
  "timestamp": "2026-11-08T12:00:00.000Z",
  "source": {"layer": "guardian"},
  "zone_id": "PORT",
  "type": "isolation_command",
  "payload": {"device_id": "S01", "action": "ISOLATE", "reason_code": "UNTRUSTED"},
  "signature": "hmac-sha256:9beb655db607ded5b460554404b5604c713400991b76967cb599de5fa5b01a0c"
}
```

### quarantine_command

```json
{
  "schema_version": "1.0",
  "event_id": "evt-qua-1",
  "seq": 3,
  "timestamp": "2026-11-08T12:00:00.000Z",
  "source": {"layer": "guardian"},
  "zone_id": "PORT",
  "type": "quarantine_command",
  "payload": {"device_id": "S01", "action": "QUARANTINE", "reason_code": "UNTRUSTED"},
  "signature": "hmac-sha256:dc11840cd9cfff332eb1ba413d473fde1020d84a8c030639f0b4ba767f5793a7"
}
```

### release_command

```json
{
  "schema_version": "1.0",
  "event_id": "evt-rel-1",
  "seq": 4,
  "timestamp": "2026-11-08T12:00:00.000Z",
  "source": {"layer": "guardian"},
  "zone_id": "PORT",
  "type": "release_command",
  "payload": {"device_id": "S01", "action": "RELEASE", "reason_code": "RESTORED"},
  "signature": "hmac-sha256:227a1863eb3df191647bf43626ac200e5d80cb4e3a8de8a563f55978a02a3d91"
}
```

Guardian signs outbound verdicts and containment commands with the Guardian key before an adapter sends them. The Twin is expected to verify isolation, quarantine, and release commands. The Brain is expected to verify trust verdicts and device status.

## Reason codes

`SCHEMA_INVALID` responses also include `"fields"`. No response includes a stack trace, a key, a signature, or payload contents. `event_id` is included when the sender's value is safe to echo.

| Code | HTTP | Message |
|---|---|---|
| `MESSAGE_TOO_LARGE` | 413 | Message exceeds the maximum allowed size. |
| `MALFORMED_JSON` | 422 | Message body is not valid JSON. |
| `SCHEMA_INVALID` | 422 | Message does not match the required envelope. |
| `SIGNATURE_MISSING` | 401 | Message signature is missing. |
| `SIGNATURE_INVALID` | 401 | Message signature is invalid. |
| `UNKNOWN_SENDER` | 401 | Sender is not a recognized layer. |
| `FORBIDDEN` | 403 | Caller is not allowed to perform this operation. |
| `SOURCE_MISMATCH` | 403 | Canonical source does not match the authenticated sender. |
| `STALE_TIMESTAMP` | 422 | Message timestamp is too old. |
| `FUTURE_TIMESTAMP` | 422 | Message timestamp is too far in the future. |
| `REPLAY` | 409 | This event has already been processed. |
| `RATE_LIMITED` | 429 | Too many messages from this source. |

Example:

```json
{"error": "SIGNATURE_INVALID", "message": "Message signature is invalid.", "event_id": "evt-8f2c1a"}
```

Sequence gaps and resets are warnings (`SEQ_GAP`, `SEQ_RESET`), not rejections. A flood is an audit event `FLOOD_SUSPECTED`, not a separate HTTP status. The HTTP status of those messages remains 429.

An unexpected failure returns `{"error": "INTERNAL_ERROR"}` with HTTP 500.

## How to point Guardian at a partner

Routes, topics, and base URLs live in `config.example.yaml` (or the file named by `GUARDIAN_CONFIG`). Change `partners.twin.base_url`, `partners.brain.base_url`, `guardian.base_url`, the `routes` list, or the `topics` list. Do not hard-code them.

HMAC keys live only in `.env`, loaded by variable name:

- `GUARDIAN_HMAC_KEY_TWIN`
- `GUARDIAN_HMAC_KEY_BRAIN`
- `GUARDIAN_HMAC_KEY_GUARDIAN`

Each key must be at least 32 characters. Generate one with `python -c "import secrets; print(secrets.token_hex(32))"`. Share it with the partner who needs it through a private channel. MQTT host, port, username, and password override the YAML when `MQTT_HOST`, `MQTT_PORT`, `MQTT_USERNAME`, or `MQTT_PASSWORD` are set.

Run one process: `python run_guardian.py`, which starts `uvicorn guardian.main:app --workers 1`.
