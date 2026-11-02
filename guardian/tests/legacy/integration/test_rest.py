"""REST error contract for the attacks the gate knows how to name."""

import json

from tests.support import BRAIN_KEY, TWIN_KEY, build_client, raw, reading, signed


def _path(app, operation: str) -> str:
    return app.state.config.route(operation).path


def test_valid_reading_returns_200() -> None:
    client, app, clock = build_client()
    body = signed(reading(timestamp=clock.stamp()))
    response = client.post(_path(app, "publish_reading"), content=raw(body))
    assert response.status_code == 200
    assert response.json() == {"status": "accepted", "event_id": "evt-8f2c1a"}
    assert app.state.core.received[0]["envelope"]["event_id"] == "evt-8f2c1a"


def test_tampered_reading_returns_401() -> None:
    client, app, clock = build_client()
    body = signed(reading(timestamp=clock.stamp()))
    body["payload"] = {"metric": "water_level", "value": 1, "unit": "cm"}
    response = client.post(_path(app, "publish_reading"), content=raw(body))
    assert response.status_code == 401
    assert response.json() == {
        "error": "SIGNATURE_INVALID",
        "message": "Message signature is invalid.",
        "event_id": "evt-8f2c1a",
    }


def test_forbidden_operation_returns_403() -> None:
    client, app, clock = build_client()
    body = signed(reading(timestamp=clock.stamp()))
    response = client.post(_path(app, "report_decision"), content=raw(body))
    assert response.status_code == 403
    assert response.json()["error"] == "FORBIDDEN"
    assert "message" in response.json()
    assert TWIN_KEY not in response.text


def test_replay_returns_409() -> None:
    client, app, clock = build_client()
    payload = raw(signed(reading(timestamp=clock.stamp())))
    path = _path(app, "publish_reading")
    assert client.post(path, content=payload).status_code == 200
    response = client.post(path, content=payload)
    assert response.status_code == 409
    assert response.json()["error"] == "REPLAY"
    assert response.json()["event_id"] == "evt-8f2c1a"


def test_oversize_body_returns_413() -> None:
    client, app, _clock = build_client(max_message_bytes=64)
    response = client.post(_path(app, "publish_reading"), content=b"{" * 80)
    assert response.status_code == 413
    assert response.json()["error"] == "MESSAGE_TOO_LARGE"
    assert "signature" not in response.text


def test_invalid_schema_returns_422_with_fields() -> None:
    client, app, clock = build_client()
    body = reading(timestamp=clock.stamp())
    del body["seq"]
    body["payload"] = {"marker": "SHOULD_NOT_LEAK"}
    response = client.post(_path(app, "publish_reading"), content=raw(signed(body)))
    assert response.status_code == 422
    document = response.json()
    assert document["error"] == "SCHEMA_INVALID"
    assert "seq" in document["fields"]
    assert "SHOULD_NOT_LEAK" not in response.text


def test_rate_limit_returns_429() -> None:
    client, app, clock = build_client(rate_burst=1, rate_per_source=1e-6)
    path = _path(app, "publish_reading")
    first = signed(reading(timestamp=clock.stamp(), seq=1, event_id="evt-1"))
    second = signed(reading(timestamp=clock.stamp(), seq=2, event_id="evt-2"))
    assert client.post(path, content=raw(first)).status_code == 200
    response = client.post(path, content=raw(second))
    assert response.status_code == 429
    assert response.json()["error"] == "RATE_LIMITED"
    assert response.json()["message"] == "Too many messages from this source."


def test_brain_decision_is_allowed() -> None:
    client, app, clock = build_client()
    body = signed(
        reading(
            timestamp=clock.stamp(),
            source={"layer": "brain"},
            type="decision",
            event_id="evt-decision",
            payload={"decision": "HOLD", "reason_code": "NONE"},
        ),
        BRAIN_KEY,
    )
    response = client.post(_path(app, "report_decision"), content=raw(body))
    assert response.status_code == 200
    assert response.json()["status"] == "accepted"


def test_health_reveals_no_secrets() -> None:
    client, app, _clock = build_client()
    response = client.get(_path(app, "health"))
    assert response.status_code == 200
    assert set(response.json()) == {"status", "contract_version", "degraded"}
    assert response.json() == {"status": "ok", "contract_version": "1.0", "degraded": False}
    assert TWIN_KEY not in response.text
    assert "hmac" not in response.text.lower()


def test_openapi_documents_the_error_schema() -> None:
    client, app, _clock = build_client()
    spec = client.get("/openapi.json")
    assert spec.status_code == 200
    document = spec.json()
    assert "PublicError" in document["components"]["schemas"]
    assert "429" in document["paths"][_path(app, "publish_reading")]["post"]["responses"]
    docs = client.get("/docs")
    assert docs.status_code == 200


def test_unexpected_core_error_is_a_generic_500() -> None:
    class Boom:
        def handle(self, envelope, warnings):
            raise RuntimeError("INTERNAL_DETAIL " + TWIN_KEY)

    client, app, clock = build_client(core=Boom())
    response = client.post(
        _path(app, "publish_reading"),
        content=raw(signed(reading(timestamp=clock.stamp()))),
    )
    assert response.status_code == 500
    assert response.json() == {"error": "INTERNAL_ERROR"}
    assert "INTERNAL_DETAIL" not in response.text
    assert "Traceback" not in response.text
    assert TWIN_KEY not in response.text


def test_config_routes_match_the_interface_card() -> None:
    _client, app, _clock = build_client()
    config = app.state.config
    assert config.route("publish_reading").path == "/v1/readings"
    assert config.route("report_actuator_state").path == "/v1/actuator-states"
    assert config.route("ack_command").path == "/v1/command-acks"
    assert config.route("request_verdict").path == "/v1/verdicts/query"
    assert config.route("get_device_status").path == "/v1/devices/status"
    assert config.route("report_decision").path == "/v1/decisions"
    assert config.route("health").path == "/health"
    topics = {topic.operation: topic.topic for topic in config.topics}
    assert topics["publish_reading"] == "city/twin/readings/{device_id}"
    assert topics["ack_command"] == "city/twin/acks"
    assert topics["publish_command"] == "city/guardian/commands"
    loaded = json.dumps({"port": config.mqtt_port})
    assert "1883" in loaded
