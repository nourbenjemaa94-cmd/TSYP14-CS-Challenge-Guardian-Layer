"""Production composition and HTTP security regression tests."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from guardian import main
from guardian.adapters.communication.brain import RestBrainOutputAdapter
from guardian.adapters.contract.errors import MappingErrorCode
from guardian.adapters.contract.mapper import GenericMapper
from guardian.adapters.contract.production import production_profiles
from guardian.adapters.contract.profile import MappingProfile
from guardian.config import Settings
from guardian.core.anomaly_detector import AnomalyDetector
from guardian.core.containment import ContainmentEngine
from guardian.core.trust_assessor import TrustAssessor
from guardian.orchestration.pipeline import TransportContext
from guardian.security.authentication import sign_envelope
from guardian.security.errors import SecurityConfigurationError
from guardian.security.freshness import format_timestamp
from guardian.security.gate import SecurityGate

KEYS = {
    "GUARDIAN_HMAC_KEY_TWIN": "t" * 32,
    "GUARDIAN_HMAC_KEY_BRAIN": "b" * 32,
    "GUARDIAN_HMAC_KEY_GUARDIAN": "g" * 32,
}


@pytest.fixture(autouse=True)
def reset_pipeline(monkeypatch: pytest.MonkeyPatch):
    previous = main._pipeline
    previous_error = main._startup_error
    main._pipeline = None
    main._startup_error = None
    yield
    main._pipeline = previous
    main._startup_error = previous_error


@pytest.fixture
def http_client(monkeypatch: pytest.MonkeyPatch):
    for name, value in KEYS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(
        RestBrainOutputAdapter,
        "send_to_brain",
        lambda _self, _payload: asyncio.sleep(0),
    )
    with TestClient(main.app) as client:
        yield client


def envelope(
    *,
    timestamp: str | None = None,
    source: str = "twin",
    seq: int = 1,
    message_type: str = "sensor_reading",
    payload: dict | None = None,
) -> dict:
    body = {
        "schema_version": "1.0",
        "schema_id": {
            "sensor_reading": "twin-canonical-v1",
            "sensor_reading_batch": "twin-canonical-batch-v1",
        }.get(message_type, "unknown-schema"),
        "event_id": f"evt-http-{seq}",
        "seq": seq,
        "timestamp": timestamp or format_timestamp(datetime.now(UTC)),
        "source": {"layer": source, "device_id": "S01"},
        "zone_id": "PORT",
        "type": message_type,
        "payload": payload if payload is not None else {"metric": "water_level", "value": 180, "unit": "cm"},
    }
    key = KEYS["GUARDIAN_HMAC_KEY_" + source.upper()]
    return sign_envelope(body, key)


def post_signed(client: TestClient, body: dict) -> object:
    return client.post("/api/v1/telemetry", content=json.dumps(body).encode())


class RecordingMapper(GenericMapper):
    def __init__(self):
        super().__init__()
        self.adapters: list[str] = []

    def map_message(self, message, profile, source_adapter="unknown"):
        self.adapters.append(source_adapter)
        return super().map_message(message, profile, source_adapter)


def test_production_pipeline_uses_real_security_contract_and_output(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in KEYS.items():
        monkeypatch.setenv(name, value)

    pipeline = main._default_pipeline()

    assert isinstance(pipeline.security, SecurityGate)
    assert isinstance(pipeline.contract, GenericMapper)
    assert isinstance(pipeline.output, RestBrainOutputAdapter)
    assert isinstance(pipeline.detector, AnomalyDetector)
    assert isinstance(pipeline.assessor, TrustAssessor)
    assert isinstance(pipeline.containment, ContainmentEngine)
    assert pipeline.detector.history is pipeline.assessor.history is pipeline.containment.history


@pytest.mark.parametrize(
    ("context", "expected"),
    [
        (TransportContext(transport="mqtt"), "mqtt"),
        (TransportContext(transport="rest"), "rest"),
        (None, "rest"),
    ],
)
def test_secure_mapping_uses_validated_transport_protocol(
    monkeypatch: pytest.MonkeyPatch,
    context: TransportContext | None,
    expected: str,
) -> None:
    for name, value in KEYS.items():
        monkeypatch.setenv(name, value)

    pipeline = main._default_pipeline()
    mapper = RecordingMapper()
    pipeline.contract = mapper
    pipeline.output.send_to_brain = AsyncMock(return_value=True)
    body = envelope(seq=20 if expected == "mqtt" else 21)

    asyncio.run(
        pipeline.process_incoming(
            json.dumps(body).encode(), MagicMock(), transport_context=context
        )
    )

    assert mapper.adapters == [expected]


def test_transport_context_rejects_protocol_outside_adapter_registry() -> None:
    with pytest.raises(ValueError, match="mqtt, rest"):
        TransportContext(transport="smtp")  # type: ignore[arg-type]


def test_missing_hmac_keys_prevent_activation_and_readiness(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)  # no developer .env in the working directory
    for name in KEYS:
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(SecurityConfigurationError):
        main._default_pipeline()

    response = asyncio.run(main.readiness_check())
    assert response.status_code == 503

    assert asyncio.run(main.health_check())["status"] == "ALIVE"


def test_http_refuses_messages_when_pipeline_is_not_ready(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)  # no developer .env in the working directory
    for name in KEYS:
        monkeypatch.delenv(name, raising=False)

    with TestClient(main.app) as client:
        response = client.post("/api/v1/telemetry", content=b"{}")

    assert response.status_code == 503
    assert response.json()["error"] == "PIPELINE_NOT_CONFIGURED"


def test_unsigned_http_message_is_rejected_before_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in KEYS.items():
        monkeypatch.setenv(name, value)

    with TestClient(main.app) as client:
        response = client.post("/api/v1/telemetry", content=b"{}")

    assert response.status_code == 401
    assert response.json()["error"] == "SIGNATURE_MISSING"


def test_malformed_json_is_publicly_rejected_without_raw_body(http_client: TestClient) -> None:
    response = http_client.post("/api/v1/telemetry", content=b"not-json-token-secret")

    assert response.status_code == 422
    assert response.json() == {
        "error": "MALFORMED_JSON",
        "message": "Message body is not valid JSON.",
    }
    assert "not-json-token-secret" not in response.text


def test_empty_http_body_is_a_schema_rejection(http_client: TestClient) -> None:
    response = http_client.post("/api/v1/telemetry", content=b"")

    assert response.status_code == 422
    assert response.json()["error"] == "SCHEMA_INVALID"
    assert "detail" not in response.json()


def test_rejected_http_message_does_not_reach_numeric_core(
    http_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = main._pipeline
    assert pipeline is not None
    core_calls: list[object] = []
    monkeypatch.setattr(
        pipeline,
        "_process_canonical",
        lambda *args, **kwargs: core_calls.append((args, kwargs)),
    )

    response = http_client.post(
        "/api/v1/telemetry",
        content=json.dumps({"token": "do-not-echo"}).encode(),
    )

    assert response.status_code == 401
    assert response.json()["error"] == "SIGNATURE_MISSING"
    assert "do-not-echo" not in response.text
    assert core_calls == []


def test_altered_signature_and_wrong_key_are_rejected(http_client: TestClient) -> None:
    altered = envelope()
    altered["payload"]["value"] = 181
    wrong_key = sign_envelope(
        {key: value for key, value in envelope().items() if key != "signature"},
        KEYS["GUARDIAN_HMAC_KEY_BRAIN"],
    )

    for body in (altered, wrong_key):
        response = post_signed(http_client, body)
        assert response.status_code == 401
        assert response.json()["error"] == "SIGNATURE_INVALID"


def test_forbidden_source_is_rejected(http_client: TestClient) -> None:
    response = post_signed(http_client, envelope(source="guardian"))
    assert response.status_code == 403
    assert response.json()["error"] == "FORBIDDEN"


@pytest.mark.parametrize(
    ("delta", "code"),
    [
        (timedelta(seconds=-60), "STALE_TIMESTAMP"),
        (timedelta(seconds=60), "FUTURE_TIMESTAMP"),
    ],
)
def test_old_and_future_timestamps_are_rejected(
    http_client: TestClient, delta: timedelta, code: str
) -> None:
    timestamp = format_timestamp(datetime.now(UTC) + delta)
    response = post_signed(http_client, envelope(timestamp=timestamp, seq=20))
    assert response.status_code == 422
    assert response.json()["error"] == code


def test_replay_is_rejected(http_client: TestClient) -> None:
    body = envelope(seq=30)
    first = post_signed(http_client, body)
    second = post_signed(http_client, body)

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["error"] == "REPLAY"


def test_excessive_rate_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIAN_RATE_BURST", "1")
    monkeypatch.setenv("GUARDIAN_RATE_PER_SOURCE", "0.001")
    monkeypatch.setenv("GUARDIAN_HMAC_KEY_TWIN", KEYS["GUARDIAN_HMAC_KEY_TWIN"])
    monkeypatch.setenv("GUARDIAN_HMAC_KEY_BRAIN", KEYS["GUARDIAN_HMAC_KEY_BRAIN"])
    monkeypatch.setenv("GUARDIAN_HMAC_KEY_GUARDIAN", KEYS["GUARDIAN_HMAC_KEY_GUARDIAN"])
    monkeypatch.setattr(RestBrainOutputAdapter, "send_to_brain", lambda _self, _payload: asyncio.sleep(0))

    with TestClient(main.app) as client:
        first = post_signed(client, envelope(seq=40))
        second = post_signed(client, envelope(seq=41))

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["error"] == "RATE_LIMITED"


def test_body_over_65536_bytes_is_rejected(http_client: TestClient) -> None:
    response = http_client.post("/api/v1/telemetry", content=b"{" + b"a" * 65536 + b"}")
    assert response.status_code == 413
    assert response.json()["error"] == "MESSAGE_TOO_LARGE"


def test_production_profiles_are_validated() -> None:
    profiles = production_profiles()
    assert set(profiles) >= {
        "sensor_reading",
        "sensor_reading_batch",
        "device_status",
        "discrete_event",
        "media_reference",
    }
    assert all(isinstance(profile, MappingProfile) for profile in profiles.values())


def test_water_level_alias_and_meters_are_normalized(http_client: TestClient) -> None:
    response = post_signed(
        http_client,
        envelope(payload={"metric": "waterLevel", "value": 1.8, "unit": "m"}),
    )
    assert response.status_code == 200
    assert response.json()["metric"] == "water_level"
    assert response.json()["value"] == 180.0
    assert response.json()["unit"] == "cm"


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ({"metric": "waterLevel", "value": "not-a-number", "unit": "m"}, MappingErrorCode.INVALID_VALUE),
        ({}, MappingErrorCode.PATH_NOT_FOUND),
        ({"metric": "waterLevel", "value": 1, "unit": "furlong"}, MappingErrorCode.UNSUPPORTED_UNIT),
    ],
)
def test_invalid_measurement_payloads_are_rejected(
    http_client: TestClient, payload: dict, code: MappingErrorCode
) -> None:
    response = post_signed(http_client, envelope(payload=payload, seq=60))
    assert response.status_code == 422
    assert response.json()["error"] == code.value


def test_batch_of_two_sensor_events_reaches_core_as_two_sensor_events(http_client: TestClient) -> None:
    stamp = format_timestamp(datetime.now(UTC))
    response = post_signed(
        http_client,
        envelope(
            message_type="sensor_reading_batch",
            seq=70,
            payload={
                "readings": [
                    {"sensor_id": "S01", "timestamp": stamp, "metric": "waterLevel", "value": 1.0, "unit": "m"},
                    {"sensor_id": "S02", "timestamp": stamp, "metric": "waterLevel", "value": 2.0, "unit": "m"},
                ]
            },
        ),
    )
    body = response.json()
    assert response.status_code == 200
    assert body["status"] == "ACCEPTED"
    assert [event["sensor_id"] for event in body["events"]] == ["S01", "S02"]
    assert [event["value"] for event in body["events"]] == [100.0, 200.0]


def test_unknown_schema_is_publicly_rejected(http_client: TestClient) -> None:
    response = post_signed(
        http_client,
        envelope(message_type="future_partner_schema", seq=80),
    )
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "ONBOARDING_PENDING"
    assert body["error"] == MappingErrorCode.ONBOARDING_PENDING.value
    assert body["fingerprint"]


def test_guardian_can_reset_unmappable_profile(http_client: TestClient) -> None:
    pending = post_signed(
        http_client,
        envelope(message_type="future_partner_schema", seq=81),
    )
    fingerprint = pending.json()["fingerprint"]
    pipeline = main._pipeline
    assert pipeline is not None and pipeline.onboarding is not None
    record = None
    for _ in range(50):
        record = pipeline.onboarding.registry.get(fingerprint)
        if record is not None and record.status == "UNMAPPABLE":
            break
        time.sleep(0.02)
    else:
        pytest.fail("onboarding did not mark the unknown shape UNMAPPABLE")

    twin_reset = http_client.post(
        f"/api/v1/profiles/{fingerprint}/reset",
        content=json.dumps(envelope(message_type="profile_reset", seq=82)).encode(),
    )
    assert twin_reset.status_code == 403

    reset = http_client.post(
        f"/api/v1/profiles/{fingerprint}/reset",
        content=json.dumps(envelope(source="guardian", message_type="profile_reset", seq=83)).encode(),
    )
    assert reset.status_code == 200
    assert reset.json() == {"status": "RESET", "fingerprint": fingerprint}
    assert pipeline.onboarding.registry.get(fingerprint) is None


def _cors_app() -> FastAPI:
    """Fresh app wired exactly like ``main.app``'s CORS layer, built after env changes."""
    application = FastAPI()
    application.add_middleware(CORSMiddleware, **main._cors_middleware_options())

    @application.post("/api/v1/telemetry")
    async def telemetry() -> dict:
        return {}

    return application


def _preflight(client: TestClient, origin: str):
    return client.options(
        "/api/v1/telemetry",
        headers={"Origin": origin, "Access-Control-Request-Method": "POST"},
    )


def test_configured_cors_origins_are_applied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIAN_CORS_ORIGINS", "https://qa.example, https://ops.example")

    client = TestClient(_cors_app())
    allowed = _preflight(client, "https://qa.example")
    refused = _preflight(client, "https://other.example")

    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "https://qa.example"
    assert allowed.headers.get("access-control-allow-credentials") == "true"
    assert "access-control-allow-origin" not in refused.headers


def test_cors_origins_come_from_yaml_when_env_is_unset(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.delenv("GUARDIAN_CORS_ORIGINS", raising=False)
    config_path = tmp_path / "cors.yaml"
    config_path.write_text("server:\n  cors_origins: ['https://yaml.example']\n", encoding="utf-8")
    monkeypatch.setenv("GUARDIAN_CONFIG", str(config_path))

    assert main._cors_origins() == ["https://yaml.example"]
    assert main._cors_middleware_options()["allow_credentials"] is True


def test_wildcard_cors_default_never_allows_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.delenv("GUARDIAN_CORS_ORIGINS", raising=False)
    monkeypatch.setenv("GUARDIAN_CONFIG", str(tmp_path / "absent.yaml"))

    options = main._cors_middleware_options()
    assert options["allow_origins"] == ["*"]
    assert options["allow_credentials"] is False

    client = TestClient(_cors_app())
    response = _preflight(client, "https://anyone.example")
    assert response.headers["access-control-allow-origin"] == "*"
    assert "access-control-allow-credentials" not in response.headers


def test_settings_load_parses_cors_origin_list(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings.load(
        environ={**KEYS, "GUARDIAN_CORS_ORIGINS": "https://a.example,https://b.example"},
    )
    assert settings.server.cors_origins == ["https://a.example", "https://b.example"]
