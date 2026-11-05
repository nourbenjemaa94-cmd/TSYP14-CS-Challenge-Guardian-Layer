"""A Twin envelope signed with the Brain key is not a Twin message."""

from tests.support import BRAIN_KEY, make_client, reading, signed


def test_forged_sender_is_rejected(monkeypatch, tmp_path, caplog) -> None:
    with make_client(monkeypatch, tmp_path) as app:
        response = app.post(signed(reading(), BRAIN_KEY))

    assert response.status_code == 401
    assert response.json()["error"] == "SIGNATURE_INVALID"
    assert app.sent_to_brain == []
    assert "SIGNATURE_INVALID" in caplog.text
    assert "SECURITY_REJECTED" in caplog.text
