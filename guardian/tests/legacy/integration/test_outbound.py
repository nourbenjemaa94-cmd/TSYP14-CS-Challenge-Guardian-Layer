"""Verdicts and containment commands are signed, and a modified copy fails."""

from copy import deepcopy

from tests.support import BRAIN_KEY, GUARDIAN_KEY, TWIN_KEY, build_client, raw, reading, signed

from guardian.security.authentication import verify_signature


def test_outbound_verdict_and_commands_verify_only_with_the_guardian_key() -> None:
    _client, app, clock = build_client()
    signer = app.state.signer
    messages = [
        signer.sign(
            message_type="trust_verdict",
            payload={"event_ids": ["evt-8f2c1a"], "verdict": "INSUFFICIENT_DATA", "reason_code": "CORE_STUB"},
            zone_id="PORT",
            timestamp=clock.stamp(),
        ),
        signer.sign(
            message_type="isolation_command",
            payload={"device_id": "S01", "action": "ISOLATE", "reason_code": "UNTRUSTED"},
            zone_id="PORT",
            timestamp=clock.stamp(),
        ),
        signer.sign(
            message_type="quarantine_command",
            payload={"device_id": "S01", "action": "QUARANTINE", "reason_code": "UNTRUSTED"},
            timestamp=clock.stamp(),
        ),
        signer.sign(
            message_type="release_command",
            payload={"device_id": "S01", "action": "RELEASE", "reason_code": "RESTORED"},
            timestamp=clock.stamp(),
        ),
    ]
    assert [message["seq"] for message in messages] == [0, 1, 2, 3]
    for message in messages:
        assert verify_signature(message, GUARDIAN_KEY)
        assert not verify_signature(message, TWIN_KEY)
        tampered = deepcopy(message)
        tampered["payload"] = dict(tampered["payload"])
        tampered["payload"]["reason_code"] = "CHANGED"
        assert not verify_signature(tampered, GUARDIAN_KEY)


def test_verdict_query_returns_a_signed_reply() -> None:
    client, app, clock = build_client()
    body = signed(
        reading(
            timestamp=clock.stamp(),
            source={"layer": "brain"},
            type="verdict_request",
            event_id="evt-query",
            payload={"event_ids": ["evt-8f2c1a"]},
        ),
        BRAIN_KEY,
    )
    response = client.post(app.state.config.route("request_verdict").path, content=raw(body))
    assert response.status_code == 200
    reply = response.json()
    assert verify_signature(reply, GUARDIAN_KEY)
    assert reply["type"] == "trust_verdict"
    assert reply["payload"]["verdict"] == "INSUFFICIENT_DATA"
    assert reply["payload"]["reason_code"] == "CORE_STUB"
    tampered = deepcopy(reply)
    tampered["payload"] = dict(tampered["payload"])
    tampered["payload"]["verdict"] = "TRUSTED"
    assert not verify_signature(tampered, GUARDIAN_KEY)
