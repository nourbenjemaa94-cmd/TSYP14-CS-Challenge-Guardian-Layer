"""C17 independent regression checks for persistent profile selection."""

import pytest

from guardian.adapters.contract.errors import MappingError, MappingErrorCode
from guardian.adapters.contract.profile import load_profile
from guardian.adapters.contract.registry import ProfileRegistry


def _profile(profile_id: str, schema_id: str, version: str = "1.0"):
    return load_profile(
        {
            "profile_id": profile_id,
            "schema_id": schema_id,
            "version": version,
            "event_kind": "measurement",
            "metric_value": "water_level",
            "value_path": "$.payload.value",
            "unit_path": "$.payload.unit",
        }
    )


def test_c17_active_schema_versions_are_exactly_selected_and_twin_isolated(tmp_path):
    registry = ProfileRegistry(tmp_path)
    registry.register_profile(
        _profile("water-v1", "water", "1.0"),
        twin_identity="twin:A",
        event_type="reading",
        status="ACTIVE",
    )
    registry.register_profile(
        _profile("temperature-v1", "temperature", "1.0"),
        twin_identity="twin:A",
        event_type="reading",
        status="ACTIVE",
    )
    registry.register_profile(
        _profile("water-v2", "water", "2.0"),
        twin_identity="twin:A",
        event_type="reading",
        status="ACTIVE",
    )

    assert registry.select(
        twin_identity="twin:A",
        event_type="reading",
        schema_id="temperature",
        schema_version="1.0",
    ).profile_id == "temperature-v1"
    assert registry.select(
        twin_identity="twin:A",
        event_type="reading",
        schema_id="water",
        schema_version="2.0",
    ).profile_id == "water-v2"
    with pytest.raises(MappingError) as exc:
        registry.select(
            twin_identity="twin:B",
            event_type="reading",
            schema_id="water",
            schema_version="1.0",
        )
    assert exc.value.code is MappingErrorCode.UNKNOWN_SCHEMA


def test_c17_pending_proposal_is_not_promoted_but_builtin_is_explicitly_promoted(tmp_path):
    registry = ProfileRegistry(tmp_path)
    proposal = registry.ensure_active(
        _profile("ai-proposal", "builtin-schema"),
        twin_identity="twin:A",
        event_type="reading",
    )
    assert proposal.status == "PENDING"

    with pytest.raises(MappingError) as exc:
        registry.select(
            twin_identity="twin:A",
            event_type="reading",
            schema_id="builtin-schema",
            schema_version="1.0",
        )
    assert exc.value.code is MappingErrorCode.UNKNOWN_SCHEMA

    builtin = registry.ensure_builtin_active(
        _profile("builtin", "builtin-schema"),
        twin_identity="twin:A",
        event_type="reading",
    )
    assert builtin.status == "ACTIVE"
    assert registry.get(proposal.fingerprint).status == "PENDING"
    restarted = ProfileRegistry(tmp_path)
    assert restarted.select(
        twin_identity="twin:A",
        event_type="reading",
        schema_id="builtin-schema",
        schema_version="1.0",
    ).profile_id == "builtin"
