"""Heuristic and LLM proposers. Offline only; the LLM uses a fake provider."""

from __future__ import annotations

import json

import pytest

from guardian.adapters.contract.ai_mapper import AIMapper, NoOpinion
from guardian.adapters.contract.errors import MappingError, MappingErrorCode
from guardian.adapters.contract.llm.ollama import ProviderUnavailable
from guardian.adapters.contract.proposers import HeuristicProposer, LLMProposer, load_synonyms
from guardian.adapters.contract.schema_reader import SchemaReader
from mocks.mock_twin import TWIN_ALT_PAYLOAD

from .conftest import envelope


def _describe(payload: dict, schema_id: str = "sample"):
    return SchemaReader().read_sample(envelope(payload, type="water_reading"), schema_id)


def test_synonyms_file_loads():
    table = load_synonyms()
    assert table["level_of_water"]["metric"] == "water_level"
    assert table["unit_of_measure"]["role"] == "unit"


def test_heuristic_maps_the_diagram_sample():
    sample = _describe({"levelOfWater": 1.8, "unit": "m", "sensor_id": "S01"}, "twin-diagram")
    proposal = HeuristicProposer().propose(sample)
    assert proposal is not None
    assert proposal.proposer == "heuristic"
    assert proposal.profile.metric_value == "water_level"
    assert proposal.profile.value_path == "$.payload.levelOfWater"
    assert proposal.profile.unit_path == "$.payload.unit"


def test_heuristic_maps_the_twin_alt_sample():
    proposal = HeuristicProposer().propose(_describe(TWIN_ALT_PAYLOAD, "unknown-schema"))
    assert proposal is not None
    assert proposal.profile.value_path == "$.payload.levelOfWater"
    assert proposal.profile.unit_path == "$.payload.unitOfMeasure"
    assert proposal.profile.sensor_id_path == "$.payload.gauge"
    assert proposal.profile.metric_value == "water_level"


def test_heuristic_maps_the_canonical_sample():
    proposal = HeuristicProposer().propose(
        _describe({"metric": "water_level", "value": 180, "unit": "cm"}, "twin-canonical-v1")
    )
    assert proposal is not None
    assert proposal.profile.metric_path == "$.payload.metric"
    assert proposal.profile.value_path == "$.payload.value"
    assert proposal.profile.unit_path == "$.payload.unit"


def test_heuristic_returns_none_for_unrelated_payload():
    assert HeuristicProposer().propose(_describe({"foo": "bar"})) is None


def test_llm_proposer_returns_a_validated_profile():
    reply = {
        "profile_id": "twin-x-v1",
        "schema_id": "twin-x",
        "event_kind": "measurement",
        "metric_value": "water_level",
        "value_path": "$.payload.levelOfWater",
        "unit_path": "$.payload.unit",
    }
    description = _describe({"levelOfWater": 1.8, "unit": "m"}, "twin-x")
    proposal = LLMProposer(AIMapper(lambda _prompt: json.dumps(reply))).propose(description)
    assert proposal is not None
    assert proposal.proposer == "llm"
    assert proposal.profile.profile_id == "twin-x-v1"


@pytest.mark.parametrize(
    "error",
    [
        NoOpinion("declined"),
        ProviderUnavailable("down"),
        MappingError(MappingErrorCode.INVALID_PROFILE, "bad"),
    ],
)
def test_llm_proposer_returns_none_on_provider_failure(error: Exception):
    def boom(_prompt: str) -> str:
        raise error

    assert LLMProposer(AIMapper(boom)).propose(_describe({"levelOfWater": 1.8, "unit": "m"})) is None
