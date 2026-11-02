"""A reading older than the freshness window is refused."""

from tests.support import build_client, raw, reading, signed


def test_stale_reading_is_rejected() -> None:
    client, app, clock = build_client()
    body = signed(reading(timestamp=clock.stamp(-31)))
    response = client.post(app.state.config.route("publish_reading").path, content=raw(body))
    assert response.status_code == 422
    assert response.json()["error"] == "STALE_TIMESTAMP"
    record = app.state.audit.records[0]
    assert record["code"] == "STALE_TIMESTAMP"
    assert record["stage"] == "security.accept"
    assert record["outcome"] == "rejected"
    assert app.state.core.received == []
