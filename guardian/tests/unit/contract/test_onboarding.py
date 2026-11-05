"""Onboarding manager. Fake proposers, no network, no real model."""

from __future__ import annotations

import asyncio

from guardian.adapters.contract.onboarding import OnboardingManager
from guardian.adapters.contract.proposers import HeuristicProposer
from guardian.adapters.contract.registry import ProfileRegistry
from guardian.adapters.contract.schema_reader import SchemaReader
from guardian.audit.logger import get_audit_logger
from guardian.config import ContractConfig

from .conftest import envelope


def _manager(tmp_path, min_proposers: int = 1) -> OnboardingManager:
    return OnboardingManager(
        ProfileRegistry(tmp_path / "profiles"),
        [HeuristicProposer()],
        ContractConfig(onboarding_min_proposers=min_proposers, onboarding_timeout_seconds=5),
        get_audit_logger("test.onboarding"),
    )


def test_shape_fingerprint_ignores_values(tmp_path):
    manager = _manager(tmp_path)
    first = envelope({"levelOfWater": 1.8, "unit": "m"}, type="water_reading")
    second = envelope({"levelOfWater": 9.9, "unit": "m"}, type="water_reading")
    assert manager.fingerprint_for(first, "twin:S01") == manager.fingerprint_for(second, "twin:S01")


def test_successful_onboarding_registers_probation(tmp_path, caplog):
    manager = _manager(tmp_path, min_proposers=1)
    sample = envelope({"levelOfWater": 1.8, "unit": "m", "sensor_id": "S01"}, type="water_reading")
    with caplog.at_level("INFO"):
        fingerprint = manager.submit(sample, twin_identity="twin:S01")
        asyncio.run(manager.run_now(fingerprint, "twin:S01"))
    record = manager.registry.get(fingerprint)
    assert record is not None
    assert record.status == "PROBATION"
    assert record.profile is not None
    assert record.profile.value_path == "$.payload.levelOfWater"
    for event in ("SCHEMA_UNKNOWN", "ONBOARDING_STARTED", "PROFILE_PROPOSED", "PROFILE_PROBATION"):
        assert event in caplog.text


def test_failed_gates_register_unmappable(tmp_path):
    manager = _manager(tmp_path, min_proposers=2)
    sample = envelope({"levelOfWater": 1.8, "unit": "m"}, type="water_reading")
    fingerprint = manager.submit(sample, twin_identity="twin:S01")
    asyncio.run(manager.run_now(fingerprint, "twin:S01"))
    record = manager.registry.get(fingerprint)
    assert record is not None
    assert record.status == "UNMAPPABLE"
    manager.reset(fingerprint)
    assert manager.registry.get(fingerprint) is None


def test_unrelated_payload_is_unmappable(tmp_path):
    manager = _manager(tmp_path, min_proposers=1)
    sample = envelope({"foo": "bar"}, type="mystery")
    fingerprint = manager.submit(sample, twin_identity="twin:S01")
    asyncio.run(manager.run_now(fingerprint, "twin:S01"))
    assert manager.registry.get(fingerprint).status == "UNMAPPABLE"


def test_reader_is_used(tmp_path):
    assert isinstance(_manager(tmp_path).reader, SchemaReader)
