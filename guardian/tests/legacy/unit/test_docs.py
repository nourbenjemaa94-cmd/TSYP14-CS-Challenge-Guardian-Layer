"""The interface card and the security write-up stay tied to the code."""

import json
import re
from pathlib import Path

from guardian.security.authentication import verify_signature
from guardian.security.errors import HTTP_STATUS, ReasonCode

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_KEYS = {
    "twin": "example-twin-key-do-not-use-0123456789",
    "brain": "example-brain-key-do-not-use-012345678",
    "guardian": "example-guardian-key-do-not-use-012345",
}

NAMED_TESTS = (
    "test_signature_invalid_when_tampered",
    "test_spoofed_reading_is_rejected",
    "test_wrong_key_is_signature_invalid",
    "test_forged_sender_is_rejected",
    "test_unknown_sender",
    "test_replay_rejected",
    "test_replayed_reading_is_rejected",
    "test_stale_timestamp_rejected",
    "test_stale_reading_is_rejected",
    "test_future_timestamp_rejected",
    "test_message_too_large",
    "test_malformed_json",
    "test_schema_invalid_lists_fields",
    "test_forbidden_operation",
    "test_flood_signal_once_per_window",
    "test_flood_is_rate_limited_and_audited",
    "test_source_mismatch_does_not_record_replay",
    "test_sign_outbound_and_modified_copy_fails",
    "test_rejection_audit_record_has_no_signature",
    "test_from_env_short_key_message_has_no_secret",
    "test_health_reveals_no_secrets",
    "test_ai_mapper_is_not_on_the_live_path",
)


def test_interface_documents_every_reason_code() -> None:
    text = (ROOT / "INTERFACE.md").read_text(encoding="utf-8")
    for code, status in HTTP_STATUS.items():
        assert code.value in text
        assert str(status) in text
    for code in ReasonCode:
        assert code.value in text


def test_interface_examples_verify_with_the_documented_keys() -> None:
    text = (ROOT / "INTERFACE.md").read_text(encoding="utf-8")
    for key in EXAMPLE_KEYS.values():
        assert key in text
    blocks = re.findall(r"```json\n(.*?)\n```", text, flags=re.DOTALL)
    signed = [json.loads(block) for block in blocks if '"signature"' in block]
    assert len(signed) >= 11
    for envelope in signed:
        layer = envelope["source"]["layer"]
        assert verify_signature(envelope, EXAMPLE_KEYS[layer])


def test_security_doc_names_a_test_for_every_control() -> None:
    text = (ROOT / "docs" / "SECURITY.md").read_text(encoding="utf-8")
    for name in NAMED_TESTS:
        assert name in text
