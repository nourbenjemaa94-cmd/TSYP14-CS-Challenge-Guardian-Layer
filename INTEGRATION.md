# Integration Guide: Triplet 07

This document defines integration protocols and interaction contracts between **Digital Twin (Layer 1)**, **Guardian (Layer 2)**, and **City Brain (Layer 3)**.

---

## 1. System Architecture Overview

```
┌─────────────────────┐          HTTP / MQTT          ┌─────────────────────────┐          REST / Webhook         ┌────────────────────────┐
│     Twin Layer      │ ────────────────────────────> │     Guardian Layer      │ ────────────────────────────> │    City Brain Layer    │
│  (Sensors / Sim)    │   Token-authenticated raw     │  (Sanity & Trust Gate)  │   Verified canonical events   │  (Urban Orchestration) │
└─────────────────────┘   telemetry payload           └─────────────────────────┘                               └────────────────────────┘
                                                                   │
                                                                   ▼ WebSocket: /ws/timeline
                                                      ┌─────────────────────────┐
                                                      │  Live Audit Dashboard   │
                                                      │    (Jury & Ops UI)      │
                                                      └─────────────────────────┘
```

---

## 2. Ingestion Contracts (Twin ➔ Guardian)

### Raw Telemetry Payload Specification
Twin nodes must send HTTP `POST` requests to `/api/v1/telemetry` or publish to MQTT topic `sensors/telemetry/raw`.

```json
{
  "event_id": "EVT-TWIN-20261020-001",
  "sensor_id": "S01",
  "token": "bearer-secret-token",
  "timestamp": "2026-10-20T10:00:00Z",
  "levelOfWater": 0.52,
  "unit": "m",
  "device_type": "water_depth_gauge",
  "battery_level": 94.5
}
```

### Ingestion Response Codes
- `200 OK`: Telemetry received, verified, and either forwarded to Brain or quarantined safely.
- `401 Unauthorized`: Missing or invalid authentication token / signature.
- `422 Unprocessable Entity`: Malformed JSON or schema non-compliance.

---

## 3. Forwarding Contracts (Guardian ➔ City Brain)

When a reading is evaluated with `containment_action != "ISOLATE"`, Guardian forwards the certified canonical payload to City Brain (`POST /api/v1/brain/ingest`).

```json
{
  "event_id": "EVT-TWIN-20261020-001",
  "sensor_id": "S01",
  "metric": "water_level",
  "value": 52.0,
  "unit": "cm",
  "timestamp": "2026-10-20T10:00:00Z",
  "trust_verdict": "TRUSTED",
  "reason": "NORMAL",
  "containment_action": "ALLOW",
  "signature": "guardian-hmac-sha256-verified"
}
```

---

## 4. Real-time Audit Timeline (WebSocket `/ws/timeline`)

Jury, supervisors, and operations dashboards connect via WebSocket to `/ws/timeline` to monitor every ingested message along its full causal chain:

1. `READING_RECEIVED`: Sensor input received and converted to canonical unit.
2. `GUARDIAN_VERDICT`: Anomaly detection and trust assessment results.
3. `ISOLATED` (if attack/anomaly) OR `SENT_TO_BRAIN` (if trusted/tolerated).
