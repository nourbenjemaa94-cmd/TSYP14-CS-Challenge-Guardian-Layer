"""A reading older than the freshness window is refused before Core."""

from tests.support import make_client, reading, signed


def test_stale_reading_is_rejected(monkeypatch, tmp_path, caplog) -> None:
    with make_client(monkeypatch, tmp_path) as app:
        response = app.post(signed(reading(timestamp="2020-01-01T00:00:00.000Z")))

    assert response.status_code == 422
    assert response.json()["error"] == "STALE_TIMESTAMP"
    assert app.sent_to_brain == []
    assert "STALE_TIMESTAMP" in caplog.text
    assert "SECURITY_REJECTED" in caplog.text
    assert "evt-8f2c1a" in caplog.text
