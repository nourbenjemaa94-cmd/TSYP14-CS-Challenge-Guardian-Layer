"""HTTP contract tests for signed Brain verdict queries."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from guardian import main
from guardian.adapters.communication.brain import RestBrainOutputAdapter
from guardian.audit.event_store import default_event_store
from guardian.security.authentication import sign_envelope, verify_signature
from guardian.security.freshness import format_timestamp

KEYS = {
    "GUARDIAN_HMAC_KEY_TWIN": "t" * 32,
    "GUARDIAN_HMAC_KEY_BRAIN": "b" * 32,
    "GUARDIAN_HMAC_KEY_GUARDIAN": "g" * 32,
}


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch):
    for name, value in KEYS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(RestBrainOutputAdapter, "send_to_brain", lambda _self, _payload: True)
    previous_pipeline = main._pipeline
    previous_signer = main._outbound_signer
    main._pipeline = None
    main._outbound_signer = None
    default_event_store.clear()
    with TestClient(main.app) as test_client:
        yield test_client
    default_event_store.clear()
    main._pipeline = previous_pipeline
    main._outbound_signer = previous_signer


def request_body(
    *, event_id: str = "brain-request-1", queried_event_id: str = "telemetry-1", key: str | None = None
) -> dict:
    body = {
        "schema_version": "1.0",
        "event_id": event_id,
        "seq": 1,
        "timestamp": format_timestamp(datetime.now(UTC)),
        "source": {"layer": "brain", "device_id": "planner"},
        "zone_id": "PORT",
        "type": "verdict_request",
        "payload": {"event_ids": [queried_event_id]},
    }
    return sign_envelope(body, key or KEYS["GUARDIAN_HMAC_KEY_BRAIN"])


def telemetry_body() -> dict:
    return sign_envelope(
        {
            "schema_version": "1.0",
            "schema_id": "twin-canonical-v1",
            "event_id": "telemetry-1",
            "seq": 1,
            "timestamp": format_timestamp(datetime.now(UTC)),
            "source": {"layer": "twin", "device_id": "S01"},
            "zone_id": "PORT",
            "type": "sensor_reading",
            "payload": {"metric": "water_level", "value": 180, "unit": "cm"},
        },
        KEYS["GUARDIAN_HMAC_KEY_TWIN"],
    )


def test_signed_brain_query_returns_a_runtime_signed_verdict(client: TestClient) -> None:
    ingestion = client.post("/api/v1/telemetry", content=json.dumps(telemetry_body()).encode())
    assert ingestion.status_code == 200

    response = client.post("/v1/verdicts/query", content=json.dumps(request_body()).encode())

    assert response.status_code == 200
    reply = response.json()
    assert reply["type"] == "trust_verdict"
    assert reply["payload"]["event_id"] == "telemetry-1"
    assert verify_signature(reply, KEYS["GUARDIAN_HMAC_KEY_GUARDIAN"])

    altered = copy.deepcopy(reply)
    altered["payload"]["verdict"] = "UNTRUSTED"
    assert not verify_signature(altered, KEYS["GUARDIAN_HMAC_KEY_GUARDIAN"])


def test_unsigned_brain_query_is_rejected(client: TestClient) -> None:
    response = client.post("/v1/verdicts/query", content=b"{}")

    assert response.status_code == 401
    assert response.json()["error"] == "SIGNATURE_MISSING"


def test_brain_query_signed_with_wrong_key_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/v1/verdicts/query",
        content=json.dumps(request_body(key=KEYS["GUARDIAN_HMAC_KEY_TWIN"])).encode(),
    )

    assert response.status_code == 401
    assert response.json()["error"] == "SIGNATURE_INVALID"


def test_unknown_verdict_event_returns_not_found(client: TestClient) -> None:
    response = client.post(
        "/v1/verdicts/query",
        content=json.dumps(request_body(queried_event_id="does-not-exist")).encode(),
    )

    assert response.status_code == 404
    assert response.json() == {"error": "VERDICT_NOT_FOUND", "event_id": "does-not-exist"}
