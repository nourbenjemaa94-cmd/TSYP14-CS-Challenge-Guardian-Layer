"""Baseline security-gate behaviour: authenticate, authorize, validate, freshness, replay."""

import hashlib
import hmac
import json
from copy import deepcopy

import pytest
from tests.support import (
    BRAIN_KEY,
    FIXED,
    GUARDIAN_KEY,
    TWIN_KEY,
    FakeTime,
    make_gate,
    raw,
    reading,
    signed,
)

from guardian.adapters.contract.ai_mapper import suggest_mapping
from guardian.security.authentication import canonical_bytes, signature_for, verify_signature
from guardian.security.errors import ReasonCode, SecurityConfigurationError, SecurityRejection, WarningCode
from guardian.security.freshness import format_timestamp
from guardian.security.gate import SecuritySettings


def test_known_canonical_hmac_vector() -> None:
    body = {"b": 1, "a": {"d": 2, "c": 3}}
    literal = b'{"a":{"c":3,"d":2},"b":1}'
    digest = hmac.new(b"k" * 32, literal, hashlib.sha256).hexdigest()
    assert canonical_bytes(body) == literal
    assert signature_for(body, "k" * 32) == f"hmac-sha256:{digest}"


def test_unicode_is_not_escaped() -> None:
    assert canonical_bytes({"zone": "Cité"}) == '{"zone":"Cité"}'.encode()


def test_nested_list_order_is_preserved() -> None:
    assert canonical_bytes({"items": [{"z": 1, "a": 2}]}) == b'{"items":[{"a":2,"z":1}]}'


def test_valid_message_is_accepted() -> None:
    accepted = make_gate().check_inbound(raw(signed(reading())), "publish_reading")
    assert accepted.event_id == "evt-8f2c1a"
    assert accepted.authenticated_layer == "twin"
    assert accepted.warnings == ()
    assert accepted.envelope["payload"]["value"] == 180


def test_whitespace_does_not_change_the_signature() -> None:
    body = signed(reading())
    pretty = json.dumps(body, indent=2).encode()
    accepted = make_gate().check_inbound(pretty, "publish_reading")
    assert accepted.event_id == "evt-8f2c1a"


def test_unknown_fields_are_ignored() -> None:
    body = reading()
    body["debug"] = {"note": "extra"}
    accepted = make_gate().check_inbound(raw(signed(body)), "publish_reading")
    assert accepted.event_id == "evt-8f2c1a"


def test_message_too_large() -> None:
    gate = make_gate(max_message_bytes=32)
    with pytest.raises(SecurityRejection) as caught:
        gate.admit(b"{" * 40, "publish_reading")
    assert caught.value.code is ReasonCode.MESSAGE_TOO_LARGE
    assert caught.value.http_status == 413
    assert "signature" not in json.dumps(caught.value.to_public_dict())


def test_malformed_json() -> None:
    with pytest.raises(SecurityRejection) as caught:
        make_gate().admit(b"{", "publish_reading")
    assert caught.value.code is ReasonCode.MALFORMED_JSON
    assert caught.value.http_status == 422
    assert "fields" not in caught.value.to_public_dict()


def test_json_array_rejected() -> None:
    with pytest.raises(SecurityRejection) as caught:
        make_gate().admit(b"[1]", "publish_reading")
    assert caught.value.code is ReasonCode.SCHEMA_INVALID
    assert caught.value.to_public_dict()["fields"] == ["body"]


def test_signature_missing() -> None:
    body = reading()
    with pytest.raises(SecurityRejection) as caught:
        make_gate().check_inbound(raw(body), "publish_reading")
    assert caught.value.code is ReasonCode.SIGNATURE_MISSING
    assert caught.value.http_status == 401
    assert caught.value.to_public_dict()["event_id"] == "evt-8f2c1a"


def test_signature_invalid_when_tampered() -> None:
    body = signed(reading())
    body["payload"] = {"metric": "water_level", "value": 1, "unit": "cm"}
    with pytest.raises(SecurityRejection) as caught:
        make_gate().check_inbound(raw(body), "publish_reading")
    assert caught.value.to_public_dict() == {
        "error": "SIGNATURE_INVALID",
        "message": "Message signature is invalid.",
        "event_id": "evt-8f2c1a",
    }
    assert TWIN_KEY not in str(caught.value)
    assert "hmac-sha256" not in str(caught.value)


def test_signature_malformed_prefix() -> None:
    body = reading()
    body["signature"] = "sha256:" + "ab" * 32
    with pytest.raises(SecurityRejection) as caught:
        make_gate().check_inbound(raw(body), "publish_reading")
    assert caught.value.code is ReasonCode.SIGNATURE_INVALID


def test_unknown_sender() -> None:
    body = reading(source={"layer": "rogue"})
    with pytest.raises(SecurityRejection) as caught:
        make_gate().check_inbound(raw(signed(body)), "publish_reading")
    assert caught.value.code is ReasonCode.UNKNOWN_SENDER
    assert caught.value.http_status == 401


def test_wrong_key_is_signature_invalid() -> None:
    body = signed(reading(), BRAIN_KEY)
    with pytest.raises(SecurityRejection) as caught:
        make_gate().check_inbound(raw(body), "publish_reading")
    assert caught.value.code is ReasonCode.SIGNATURE_INVALID


def test_forbidden_operation() -> None:
    with pytest.raises(SecurityRejection) as caught:
        make_gate().check_inbound(raw(signed(reading())), "request_verdict")
    assert caught.value.code is ReasonCode.FORBIDDEN
    assert caught.value.http_status == 403


def test_brain_cannot_publish_reading() -> None:
    body = signed(reading(source={"layer": "brain"}), BRAIN_KEY)
    with pytest.raises(SecurityRejection) as caught:
        make_gate().check_inbound(raw(body), "publish_reading")
    assert caught.value.code is ReasonCode.FORBIDDEN


def test_guardian_cannot_call_inbound_operation() -> None:
    body = signed(reading(source={"layer": "guardian"}), GUARDIAN_KEY)
    with pytest.raises(SecurityRejection) as caught:
        make_gate().check_inbound(raw(body), "publish_reading")
    assert caught.value.code is ReasonCode.FORBIDDEN


def test_unknown_operation_denied() -> None:
    with pytest.raises(SecurityRejection) as caught:
        make_gate().check_inbound(raw(signed(reading())), "drop_database")
    assert caught.value.code is ReasonCode.FORBIDDEN


def test_schema_major_mismatch() -> None:
    body = signed(reading(schema_version="2.0"))
    with pytest.raises(SecurityRejection) as caught:
        make_gate().check_inbound(raw(body), "publish_reading")
    assert caught.value.code is ReasonCode.SCHEMA_INVALID
    assert caught.value.fields == ["schema_version"]


def test_schema_invalid_lists_fields_without_payload() -> None:
    body = reading()
    del body["seq"]
    body["payload"] = {"marker": "SHOULD_NOT_LEAK"}
    with pytest.raises(SecurityRejection) as caught:
        make_gate().check_inbound(raw(signed(body)), "publish_reading")
    public = json.dumps(caught.value.to_public_dict())
    assert caught.value.code is ReasonCode.SCHEMA_INVALID
    assert "seq" in (caught.value.fields or [])
    assert "SHOULD_NOT_LEAK" not in public
    assert "SHOULD_NOT_LEAK" not in str(caught.value)


def test_allowed_types_filter() -> None:
    gate = make_gate(allowed_types=("sensor_reading",))
    gate.check_inbound(raw(signed(reading())), "publish_reading")
    other = signed(reading(type="actuator_state", event_id="evt-act", seq=2))
    with pytest.raises(SecurityRejection) as caught:
        gate.check_inbound(raw(other), "report_actuator_state")
    assert caught.value.fields == ["type"]


def test_stale_timestamp_rejected() -> None:
    clock = FakeTime()
    body = signed(reading(timestamp=clock.stamp(-31)))
    with pytest.raises(SecurityRejection) as caught:
        make_gate(clock).check_inbound(raw(body), "publish_reading")
    assert caught.value.code is ReasonCode.STALE_TIMESTAMP
    assert caught.value.http_status == 422


def test_future_timestamp_rejected() -> None:
    clock = FakeTime()
    body = signed(reading(timestamp=clock.stamp(6)))
    with pytest.raises(SecurityRejection) as caught:
        make_gate(clock).check_inbound(raw(body), "publish_reading")
    assert caught.value.code is ReasonCode.FUTURE_TIMESTAMP


def test_timestamp_at_max_age_is_fresh() -> None:
    clock = FakeTime()
    body = signed(reading(timestamp=clock.stamp(-30), event_id="evt-edge-age"))
    accepted = make_gate(clock).check_inbound(raw(body), "publish_reading")
    assert accepted.event_id == "evt-edge-age"


def test_timestamp_at_skew_boundary_is_fresh() -> None:
    clock = FakeTime()
    body = signed(reading(timestamp=clock.stamp(5), event_id="evt-edge-skew"))
    accepted = make_gate(clock).check_inbound(raw(body), "publish_reading")
    assert accepted.event_id == "evt-edge-skew"


def test_replay_rejected() -> None:
    gate = make_gate()
    payload = raw(signed(reading()))
    gate.check_inbound(payload, "publish_reading")
    with pytest.raises(SecurityRejection) as caught:
        gate.check_inbound(payload, "publish_reading")
    assert caught.value.code is ReasonCode.REPLAY
    assert caught.value.http_status == 409


def test_replay_does_not_move_sequence() -> None:
    gate = make_gate()
    first = raw(signed(reading(seq=5, event_id="evt-a")))
    gate.check_inbound(first, "publish_reading")
    with pytest.raises(SecurityRejection):
        gate.check_inbound(first, "publish_reading")
    nxt = raw(signed(reading(seq=6, event_id="evt-b")))
    accepted = gate.check_inbound(nxt, "publish_reading")
    assert accepted.warnings == ()


def test_failed_auth_does_not_move_sequence() -> None:
    gate = make_gate()
    forged = signed(reading(seq=1, event_id="evt-forged"))
    forged["payload"] = {"metric": "water_level", "value": 1, "unit": "cm"}
    with pytest.raises(SecurityRejection):
        gate.check_inbound(raw(forged), "publish_reading")
    accepted = gate.check_inbound(raw(signed(reading(seq=7, event_id="evt-ok"))), "publish_reading")
    assert accepted.warnings == ()


def test_sequence_gap_warns() -> None:
    gate = make_gate()
    gate.check_inbound(raw(signed(reading(seq=1, event_id="evt-1"))), "publish_reading")
    accepted = gate.check_inbound(raw(signed(reading(seq=4, event_id="evt-4"))), "publish_reading")
    assert accepted.warnings == (WarningCode.SEQ_GAP,)


def test_sequence_reset_is_adopted() -> None:
    gate = make_gate()
    gate.check_inbound(raw(signed(reading(seq=5, event_id="evt-high"))), "publish_reading")
    reset = gate.check_inbound(raw(signed(reading(seq=1, event_id="evt-low"))), "publish_reading")
    assert reset.warnings == (WarningCode.SEQ_RESET,)
    nxt = gate.check_inbound(raw(signed(reading(seq=2, event_id="evt-next"))), "publish_reading")
    assert nxt.warnings == ()


def test_first_sequence_any_value() -> None:
    gate = make_gate()
    first = gate.check_inbound(raw(signed(reading(seq=1042, event_id="evt-high"))), "publish_reading")
    second = gate.check_inbound(raw(signed(reading(seq=1043, event_id="evt-next"))), "publish_reading")
    assert first.warnings == ()
    assert second.warnings == ()


def test_sequence_is_per_source() -> None:
    gate = make_gate()
    gate.check_inbound(raw(signed(reading(seq=3, event_id="evt-a"))), "publish_reading")
    other = signed(reading(source={"device_id": "S02"}, seq=1, event_id="evt-b"))
    accepted = gate.check_inbound(raw(other), "publish_reading")
    assert accepted.warnings == ()
    assert accepted.source_key == "twin:S02"


def test_source_mismatch_does_not_record_replay() -> None:
    gate = make_gate()
    payload = raw(signed(reading()))
    admitted = gate.admit(payload, "publish_reading")
    canonical = deepcopy(admitted.body)
    canonical["source"] = {"layer": "brain", "device_id": "S01"}
    with pytest.raises(SecurityRejection) as caught:
        gate.accept(admitted, canonical)
    assert caught.value.code is ReasonCode.SOURCE_MISMATCH
    assert caught.value.http_status == 403
    again = gate.check_inbound(payload, "publish_reading")
    assert again.event_id == "evt-8f2c1a"


def test_sign_outbound_and_modified_copy_fails() -> None:
    gate = make_gate()
    signed_out = gate.sign_outbound(
        {
            "schema_version": "1.0",
            "event_id": "evt-out-1",
            "seq": 0,
            "timestamp": format_timestamp(FIXED),
            "source": {"layer": "guardian"},
            "type": "trust_verdict",
            "payload": {
                "event_ids": ["evt-8f2c1a"],
                "verdict": "INSUFFICIENT_DATA",
                "reason_code": "CORE_STUB",
            },
        }
    )
    assert verify_signature(signed_out, GUARDIAN_KEY)
    assert not verify_signature(signed_out, TWIN_KEY)
    tampered = deepcopy(signed_out)
    tampered["payload"] = dict(tampered["payload"])
    tampered["payload"]["verdict"] = "TRUSTED"
    assert not verify_signature(tampered, GUARDIAN_KEY)


def test_outbound_must_come_from_guardian() -> None:
    body = reading()
    with pytest.raises(SecurityConfigurationError):
        make_gate().sign_outbound(body)


def test_check_inbound_without_mapping() -> None:
    accepted = make_gate().check_inbound(raw(signed(reading())), "publish_reading", None)
    assert accepted.operation == "publish_reading"


def test_settings_repr_hides_keys() -> None:
    text = repr(make_gate().settings)
    assert TWIN_KEY not in text
    assert BRAIN_KEY not in text
    assert GUARDIAN_KEY not in text


def test_from_env_missing_key() -> None:
    with pytest.raises(SecurityConfigurationError) as caught:
        SecuritySettings.from_env(environ={})
    message = str(caught.value)
    assert "GUARDIAN_HMAC_KEY_TWIN" in message
    assert "cannot start" in message


def test_from_env_short_key_message_has_no_secret() -> None:
    secret = "short-secret-value"
    with pytest.raises(SecurityConfigurationError) as caught:
        SecuritySettings.from_env(
            environ={
                "GUARDIAN_HMAC_KEY_TWIN": secret,
                "GUARDIAN_HMAC_KEY_BRAIN": BRAIN_KEY,
                "GUARDIAN_HMAC_KEY_GUARDIAN": GUARDIAN_KEY,
            }
        )
    assert secret not in str(caught.value)
    assert caught.value.__cause__ is None


def test_from_env_defaults_and_ignores_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIAN_MAX_MESSAGE_BYTES", "nope-not-used")
    loaded = SecuritySettings.from_env(
        environ={
            "GUARDIAN_HMAC_KEY_TWIN": TWIN_KEY,
            "GUARDIAN_HMAC_KEY_BRAIN": BRAIN_KEY,
            "GUARDIAN_HMAC_KEY_GUARDIAN": GUARDIAN_KEY,
        }
    )
    assert loaded.max_message_bytes == 65536
    assert loaded.schema_major == 1
    assert loaded.allowed_types == ()
    assert loaded.max_age_seconds == 30
    assert loaded.max_future_skew_seconds == 5
    assert loaded.rate_per_source == 5
    assert loaded.rate_burst == 20
    assert loaded.flood_threshold == 10


def test_invalid_numeric_setting_does_not_echo_the_value() -> None:
    leaked = "Z" * 40
    with pytest.raises(SecurityConfigurationError) as caught:
        SecuritySettings.from_env(
            environ={
                "GUARDIAN_HMAC_KEY_TWIN": TWIN_KEY,
                "GUARDIAN_HMAC_KEY_BRAIN": BRAIN_KEY,
                "GUARDIAN_HMAC_KEY_GUARDIAN": GUARDIAN_KEY,
                "GUARDIAN_MAX_MESSAGE_BYTES": leaked,
            }
        )
    assert leaked not in str(caught.value)
    assert TWIN_KEY not in str(caught.value)
    assert "GUARDIAN_MAX_MESSAGE_BYTES" in str(caught.value)


def test_dotenv_is_loaded(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "GUARDIAN_HMAC_KEY_TWIN",
        "GUARDIAN_HMAC_KEY_BRAIN",
        "GUARDIAN_HMAC_KEY_GUARDIAN",
        "GUARDIAN_RATE_BURST",
    ):
        monkeypatch.delenv(name, raising=False)
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        "\n".join(
            [
                f"GUARDIAN_HMAC_KEY_TWIN={TWIN_KEY}",
                f"GUARDIAN_HMAC_KEY_BRAIN={BRAIN_KEY}",
                f"GUARDIAN_HMAC_KEY_GUARDIAN={GUARDIAN_KEY}",
                "GUARDIAN_RATE_BURST=7",
            ]
        ),
        encoding="utf-8",
    )
    loaded = SecuritySettings.from_env(dotenv_path=dotenv)
    assert loaded.rate_burst == 7


def test_ai_mapper_is_not_on_the_live_path() -> None:
    with pytest.raises(RuntimeError, match="offline-only"):
        suggest_mapping({"partner": "field"})
