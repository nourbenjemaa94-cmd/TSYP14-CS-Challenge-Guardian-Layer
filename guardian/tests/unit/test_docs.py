"""Documented routes and reason codes must exist in code. No network."""

from pathlib import Path

from guardian.adapters.communication.rest import RestAdapter
from guardian.adapters.contract.errors import MappingErrorCode
from guardian.main import app
from guardian.security.errors import ReasonCode

ROOT = Path(__file__).resolve().parents[3]
INTERFACE = (ROOT / "guardian" / "INTERFACE.md").read_text(encoding="utf-8")
INTEGRATION = (ROOT / "INTEGRATION.md").read_text(encoding="utf-8")
SECURITY = (ROOT / "guardian" / "docs" / "SECURITY.md").read_text(encoding="utf-8")
TESTBOOK = (ROOT / "TESTBOOK.md").read_text(encoding="utf-8")


def test_documented_routes_are_registered():
    static = {route.path for route in app.routes if hasattr(route, "path")}
    for path in (
        "/api/v1/verdicts/{event_id}",
        "/api/v1/profiles/{fingerprint}/reset",
        "/v1/verdicts/query",
        "/health",
        "/ready",
        "/ws/timeline",
    ):
        assert path in static, path
        assert path in INTERFACE
    assert RestAdapter(lambda _message: None).path == "/api/v1/telemetry"
    assert "/api/v1/telemetry" in INTERFACE


def test_public_reason_codes_are_named_in_the_interface():
    for code in ReasonCode:
        assert code.value in INTERFACE or code.value in SECURITY
    for code in (
        MappingErrorCode.ONBOARDING_PENDING,
        MappingErrorCode.UNKNOWN_SCHEMA,
        MappingErrorCode.UNMAPPABLE_SCHEMA,
    ):
        assert code.value in INTERFACE


def test_docs_use_signed_envelopes_not_bearer_tokens():
    assert "Bearer" not in INTERFACE
    assert "bearer-secret-token" not in INTEGRATION
    assert "HMAC" in INTEGRATION
    assert "signature" in INTERFACE


def test_testbook_lists_jury_scenarios():
    for name in ("Normal reading", "Replay", "Tampered", "Flood", "Stale", "Spoofed", "Onboarding"):
        assert name in TESTBOOK
