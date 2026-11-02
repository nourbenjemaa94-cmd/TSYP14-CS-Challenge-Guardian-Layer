"""The same event id inside the freshness window is accepted once."""

from tests.support import build_client, raw, reading, signed


def test_replayed_reading_is_rejected() -> None:
    client, app, clock = build_client()
    payload = raw(signed(reading(timestamp=clock.stamp())))
    path = app.state.config.route("publish_reading").path
    first = client.post(path, content=payload)
    second = client.post(path, content=payload)
    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["error"] == "REPLAY"
    replay = [record for record in app.state.audit.records if record["code"] == "REPLAY"]
    assert len(replay) == 1
    assert replay[0]["outcome"] == "rejected"
    assert replay[0]["event_id"] == "evt-8f2c1a"
    assert "Guardian rejected message evt-8f2c1a: REPLAY" in app.state.audit.timeline
