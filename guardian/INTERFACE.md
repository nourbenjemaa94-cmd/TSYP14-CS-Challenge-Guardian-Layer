# Guardian Interface Specifications

## 1. REST Endpoints

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

**Responses:**
- `200 OK`: Telemetry processed. Response includes canonical message, `trust_verdict`, and `containment_action`.
- `401 Unauthorized`: Token missing or invalid.
- `422 Unprocessable Entity`: Schema validation failure.

---

### `GET /health`
Liveness and readiness health probe.

**Response (200 OK):**
```json
{
  "status": "HEALTHY",
  "version": "1.0.0",
  "layer": "GUARDIAN_GATEWAY"
}
```

---

## 2. WebSocket Endpoints

### `WS /ws/timeline`
Live audit stream designed for jury inspection, monitoring dashboards, and real-time verification (Requirement R3).

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
