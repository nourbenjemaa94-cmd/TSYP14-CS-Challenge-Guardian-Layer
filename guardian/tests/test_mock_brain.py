import json
from datetime import UTC, datetime

import pytest

from guardian.security.authentication import sign_envelope, verify_signature
from mocks.mock_brain import execute

BRAIN_KEY = "brain-test-key-012345678901234567890123456"
GUARDIAN_KEY = "guardian-test-key-012345678901234567890123"


@pytest.mark.parametrize("initial_verdict", ["TRUSTED", "UNTRUSTED"])
def test_mock_brain_tampers_with_a_different_verdict_and_preserves_original(
    tmp_path, initial_verdict: str
) -> None:
    replies: list[dict] = []

    def post(path: str, payload: bytes) -> tuple[int, dict]:
        assert path == "/v1/verdicts/query"
        request = json.loads(payload)
        assert verify_signature(request, BRAIN_KEY)
        reply = sign_envelope(
            {
                "schema_version": "1.0",
                "event_id": "evt-verdict-request",
                "type": "trust_verdict",
                "payload": {"verdict": initial_verdict},
            },
            GUARDIAN_KEY,
        )
        replies.append(reply)
        return 200, reply

    result = execute(
        post=post,
        brain_key=BRAIN_KEY,
        guardian_key=GUARDIAN_KEY,
        now=datetime(2026, 11, 4, tzinfo=UTC),
        log_dir=tmp_path,
    )

    assert result["match"] is True
    assert verify_signature(replies[0], GUARDIAN_KEY)
    assert replies[0]["payload"]["verdict"] == initial_verdict
