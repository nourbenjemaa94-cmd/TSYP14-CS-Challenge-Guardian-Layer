"""A sensor reading whose bytes no longer match its signature is refused."""

from tests.support import make_client, reading, signed


def test_spoofed_reading_is_rejected(monkeypatch, tmp_path, caplog) -> None:
    body = signed(reading())
    signature = body["signature"]
    body["payload"] = {"metric": "water_level", "value": 999, "unit": "cm"}

    with make_client(monkeypatch, tmp_path) as app:
        response = app.post(body)

    assert response.status_code == 401
    body = response.json()
    assert body["error"] == "SIGNATURE_INVALID"
    assert app.sent_to_brain == []
    assert signature not in response.text
    assert signature not in caplog.text
    assert "SECURITY_REJECTED" in caplog.text
