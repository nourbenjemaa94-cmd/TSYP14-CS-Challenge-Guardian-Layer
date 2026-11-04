import json
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from guardian.security.authentication import sign_envelope, verify_signature
from mocks.mock_brain_server import app
from mocks.mock_twin import _signed_reading, execute

GUARDIAN_KEY = "guardian-test-key-012345678901234567890123"
TWIN_KEY = "twin-test-key-012345678901234567890123456789"


def _client(monkeypatch) -> TestClient:
    monkeypatch.setenv("GUARDIAN_HMAC_KEY_GUARDIAN", GUARDIAN_KEY)
    return TestClient(app)


def _payload() -> dict[str, object]:
    return {
        "event_id": "evt-brain-1",
        "decision": "ANOMALY",
        "source": "guardian",
    }


def test_brain_mock_accepts_authentic_guardian_signature(monkeypatch) -> None:
    client = _client(monkeypatch)
    response = client.post("/api/v1/brain/ingest", json=sign_envelope(_payload(), GUARDIAN_KEY))
    assert response.status_code == 200
    assert response.json()["accepted"] is True


def test_brain_mock_rejects_missing_signature(monkeypatch) -> None:
    client = _client(monkeypatch)
    response = client.post("/api/v1/brain/ingest", json=_payload())
    assert response.status_code == 401
    assert response.json() == {"error": "SIGNATURE_MISSING"}


def test_brain_mock_rejects_wrong_or_altered_signature(monkeypatch) -> None:
    client = _client(monkeypatch)
    wrong_key = sign_envelope(_payload(), "wrong-key-012345678901234567890123456")
    altered = sign_envelope(_payload(), GUARDIAN_KEY)
    altered["decision"] = "NORMAL"

    assert client.post("/api/v1/brain/ingest", json=wrong_key).status_code == 401
    response = client.post("/api/v1/brain/ingest", json=altered)
    assert response.status_code == 401
    assert response.json() == {"error": "SIGNATURE_INVALID"}


def test_mock_twin_normal_scenario_is_signed_and_accepted(tmp_path) -> None:
    calls: list[tuple[str, bytes]] = []

    def post(path: str, payload: bytes) -> tuple[int, dict[str, object]]:
        calls.append((path, payload))
        body = json.loads(payload)
        assert verify_signature(body, TWIN_KEY)
        return 200, {"status": "ACCEPTED"}

    result = execute(
        "normal",
        post=post,
        twin_key=TWIN_KEY,
        brain_key="unused-brain-key",
        now=datetime(2026, 11, 4, tzinfo=UTC),
        log_dir=tmp_path,
        burst=3,
        flood_threshold=1,
    )

    assert result["match"] is True
    assert calls[0][0] == "/api/v1/telemetry"


def test_mock_twin_payload_signature_covers_the_body() -> None:
    payload, _ = _signed_reading(
        TWIN_KEY,
        datetime(2026, 11, 4, tzinfo=UTC),
        seq=1,
        event_id="evt-body",
    )
    body = json.loads(payload)
    assert verify_signature(body, TWIN_KEY)
    body["payload"]["value"] = 181
    assert not verify_signature(body, TWIN_KEY)
