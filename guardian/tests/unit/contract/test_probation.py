"""Probation selection, clean-map promotion, and profile_status on events."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from guardian.adapters.contract import GenericMapper, MappingError, MappingErrorCode, ProfileRegistry, load_profile
from guardian.audit.logger import get_audit_logger
from guardian.config import ContractConfig
from guardian.orchestration.pipeline import GuardianPipeline

from .conftest import envelope


def _profile():
    return load_profile(
        {
            "profile_id": "probation-water-v1",
            "schema_id": "alt-water",
            "version": "1.0",
            "event_kind": "measurement",
            "metric_value": "water_level",
            "value_path": "$.payload.value",
            "unit_path": "$.payload.unit",
        }
    )


def _register(tmp_path, status="PROBATION"):
    registry = ProfileRegistry(tmp_path)
    record = registry.register_profile(
        _profile(),
        twin_identity="twin:S01",
        event_type="water_reading",
        status=status,
    )
    return registry, record


def test_unique_probation_is_selected_when_schema_id_differs(tmp_path):
    registry, _record = _register(tmp_path)
    selected = registry.select(
        twin_identity="twin:S01",
        event_type="water_reading",
        schema_id="unknown-schema",
        schema_version="1.0",
    )
    assert selected.profile_id == "probation-water-v1"


def test_probation_profile_is_selectable(tmp_path):
    registry, _record = _register(tmp_path)
    selected = registry.select(
        twin_identity="twin:S01",
        event_type="water_reading",
        schema_id="alt-water",
        schema_version="1.0",
    )
    assert selected.schema_id == "alt-water"
    record = registry.select_record(
        twin_identity="twin:S01",
        event_type="water_reading",
        schema_id="alt-water",
        schema_version="1.0",
    )
    assert record.status == "PROBATION"


def test_clean_maps_promote_at_threshold(tmp_path):
    registry, record = _register(tmp_path)
    for _ in range(2):
        record = registry.note_clean_map(record.fingerprint, threshold=3)
        assert record.status == "PROBATION"
    record = registry.note_clean_map(record.fingerprint, threshold=3)
    assert record.status == "ACTIVE"
    assert record.promoted_at is not None
    assert record.clean_messages == 3


def test_mapping_error_resets_the_clean_counter(tmp_path):
    registry, record = _register(tmp_path)
    registry.note_clean_map(record.fingerprint, threshold=20)
    registry.note_clean_map(record.fingerprint, threshold=20)
    assert registry.get(record.fingerprint).clean_messages == 2
    registry.reset_clean_map(record.fingerprint)
    assert registry.get(record.fingerprint).clean_messages == 0
    assert registry.get(record.fingerprint).status == "PROBATION"


def _pipeline(tmp_path, threshold: int = 3) -> tuple[GuardianPipeline, object]:
    registry, record = _register(tmp_path)
    detector = MagicMock()
    detector.detect.return_value = []
    assessor = MagicMock()
    assessor.assess.return_value = ("TRUSTED", "NORMAL")
    containment = MagicMock()
    containment.evaluate_action.return_value = "ALLOW"
    store = MagicMock()
    store.get_history.return_value = []
    output = MagicMock()
    output.send_to_brain = AsyncMock(return_value=True)
    pipeline = GuardianPipeline(
        security=MagicMock(),
        contract=GenericMapper(),
        event_store=store,
        anomaly_detector=detector,
        trust_assessor=assessor,
        containment=containment,
        output_adapter=output,
        profile_registry=registry,
        onboarding=SimpleNamespace(settings=ContractConfig(probation_messages=threshold)),
        forward_to_brain=False,
    )
    return pipeline, record


def test_process_mapped_promotes_and_emits_profile_active(tmp_path, caplog):
    pipeline, record = _pipeline(tmp_path, threshold=2)
    sample = envelope({"value": 180, "unit": "cm"}, type="water_reading")
    logger = get_audit_logger("test.probation")
    with caplog.at_level("INFO"):
        asyncio.run(pipeline.process_mapped({**sample, "event_id": "EVT-P1"}, record.profile, logger))
        assert pipeline.profile_registry.get(record.fingerprint).status == "PROBATION"
        asyncio.run(pipeline.process_mapped({**sample, "event_id": "EVT-P2"}, record.profile, logger))
    promoted = pipeline.profile_registry.get(record.fingerprint)
    assert promoted.status == "ACTIVE"
    assert "PROFILE_ACTIVE" in caplog.text


def test_process_mapped_failure_resets_counter(tmp_path):
    pipeline, record = _pipeline(tmp_path, threshold=20)
    sample = envelope({"value": 180, "unit": "cm"}, type="water_reading")
    broken = envelope({"unit": "cm"}, type="water_reading")
    asyncio.run(pipeline.process_mapped({**sample, "event_id": "EVT-OK"}, record.profile))
    assert pipeline.profile_registry.get(record.fingerprint).clean_messages == 1
    with pytest.raises(MappingError) as caught:
        asyncio.run(pipeline.process_mapped({**broken, "event_id": "EVT-BAD"}, record.profile))
    assert caught.value.code is MappingErrorCode.PATH_NOT_FOUND
    assert pipeline.profile_registry.get(record.fingerprint).clean_messages == 0
    assert pipeline.profile_registry.get(record.fingerprint).status == "PROBATION"
