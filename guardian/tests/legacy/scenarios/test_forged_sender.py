"""A Twin envelope signed with the Brain key is not a Twin message."""

from tests.support import BRAIN_KEY, build_client, raw, reading, signed


def test_forged_sender_is_rejected() -> None:
    client, app, clock = build_client()
    body = signed(reading(timestamp=clock.stamp()), BRAIN_KEY)
    response = client.post(app.state.config.route("publish_reading").path, content=raw(body))
    assert response.status_code == 401
    assert response.json()["error"] == "SIGNATURE_INVALID"
    assert app.state.audit.records[0]["code"] == "SIGNATURE_INVALID"
    assert app.state.audit.records[0]["stage"] == "security.admit"
    assert app.state.core.received == []
