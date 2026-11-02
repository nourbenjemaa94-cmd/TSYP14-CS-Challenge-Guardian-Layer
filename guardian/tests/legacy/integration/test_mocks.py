"""Each mock attack mode produces the code it advertises, and writes a log."""

from tests.support import TWIN_KEY, FakeTime, build_client

from mocks.mock_brain import execute as run_brain
from mocks.mock_twin import MODES
from mocks.mock_twin import execute as run_twin


def _poster(client):
    def post(path: str, payload: bytes) -> tuple[int, dict]:
        response = client.post(path, content=payload)
        body = response.json()
        return response.status_code, body if isinstance(body, dict) else {}

    return post


def test_every_twin_mode_matches_and_writes_a_log(tmp_path) -> None:
    for mode in MODES:
        clock = FakeTime()
        client, app, _clock = build_client(clock)
        result = run_twin(
            mode,
            post=_poster(client),
            config=app.state.config,
            twin_key=app.state.gate.settings.hmac_key_twin,
            brain_key=app.state.gate.settings.hmac_key_brain,
            now=clock.wall,
            log_dir=tmp_path / mode,
            burst=app.state.gate.settings.rate_burst,
            flood_threshold=app.state.gate.settings.flood_threshold,
        )
        assert result["match"], result
        text = result["log_path"].read_text(encoding="utf-8")
        assert f"expected={result['expected']}" in text
        assert f"actual={result['actual']}" in text
        assert "hmac-sha256" not in text
        assert TWIN_KEY not in text
        if mode == "flood":
            assert any(record["code"] == "FLOOD_SUSPECTED" for record in app.state.audit.records)


def test_mock_brain_verifies_the_signed_reply(tmp_path) -> None:
    clock = FakeTime()
    client, app, _clock = build_client(clock)
    result = run_brain(
        post=_poster(client),
        config=app.state.config,
        brain_key=app.state.gate.settings.hmac_key_brain,
        guardian_key=app.state.gate.settings.hmac_key_guardian,
        now=clock.wall,
        log_dir=tmp_path,
    )
    assert result["match"], result
    text = result["log_path"].read_text(encoding="utf-8")
    assert "expected=VERIFIED" in text
    assert "actual=VERIFIED" in text
    assert "hmac-sha256" not in text
