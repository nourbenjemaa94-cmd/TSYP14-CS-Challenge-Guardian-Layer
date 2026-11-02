"""A sensor reading whose bytes no longer match its signature is refused."""

from tests.support import build_client, raw, reading, signed


def test_spoofed_reading_is_rejected() -> None:
    client, app, clock = build_client()
    body = signed(reading(timestamp=clock.stamp()))
    signature = body["signature"]
    body["payload"] = {"metric": "water_level", "value": 999, "unit": "cm"}
    path = app.state.config.route("publish_reading").path
    response = client.post(path, content=raw(body))
    assert response.status_code == 401
    assert response.json()["error"] == "SIGNATURE_INVALID"
    record = app.state.audit.records[0]
    assert record["code"] == "SIGNATURE_INVALID"
    assert record["outcome"] == "rejected"
    assert signature not in str(record)
    assert "Guardian rejected message evt-8f2c1a: SIGNATURE_INVALID" in app.state.audit.timeline
