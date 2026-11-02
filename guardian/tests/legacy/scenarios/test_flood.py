"""One device that keeps sending is rate-limited and reported once as a flood."""

from tests.support import build_client, raw, reading, signed


def test_flood_is_rate_limited_and_audited() -> None:
    client, app, clock = build_client(rate_burst=2, rate_per_source=1e-6, flood_threshold=3)
    path = app.state.config.route("publish_reading").path
    statuses = []
    for index in range(5):
        body = signed(
            reading(timestamp=clock.stamp(), seq=index, event_id=f"evt-flood-{index}")
        )
        statuses.append(client.post(path, content=raw(body)).status_code)
    assert statuses == [200, 200, 429, 429, 429]
    limited = [record for record in app.state.audit.records if record["code"] == "RATE_LIMITED"]
    floods = [record for record in app.state.audit.records if record["code"] == "FLOOD_SUSPECTED"]
    assert len(limited) == 3
    assert len(floods) == 1
    assert floods[0]["source"] == "twin:S01"
    assert floods[0]["outcome"] == "signal"
    assert any("flood suspected from twin:S01" in line for line in app.state.audit.timeline)
