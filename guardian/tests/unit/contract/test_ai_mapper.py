"""Transcription guard for the offline modules. Fake provider only; hardening is task 4."""

import json

import pytest

from guardian.adapters.contract import MappingError, MappingErrorCode
from guardian.adapters.contract.ai_mapper import AIMapper
from guardian.adapters.contract.schema_reader import SchemaReader

from .conftest import envelope

PROPOSAL = {
    "profile_id": "twin-x-v1", "schema_id": "twin-x", "event_kind": "measurement",
    "metric_value": "water_level", "value_path": "$.payload.levelOfWater", "unit_path": "$.payload.unit",
}


def test_sample_description_lists_envelope_and_payload_paths():
    description = SchemaReader().read_sample(envelope({"levelOfWater": 1.8, "unit": "m"}), "twin-x")
    paths = {field.path for field in description.fields}
    assert {"$.event_id", "$.source.device_id", "$.payload.levelOfWater", "$.payload.unit"} <= paths
    assert description.is_batch is False


def test_json_schema_type_list_does_not_crash():
    schema = {"type": "object", "properties": {"v": {"type": ["number", "null"]}}, "required": ["v"]}
    description = SchemaReader().read_json_schema(schema, "s")
    assert description.fields[0].data_type == "number|null"
    assert description.required_fields == ["$.v"]


def test_fake_provider_proposal_is_validated_like_any_profile():
    description = SchemaReader().read_sample(envelope({"levelOfWater": 1.8, "unit": "m"}), "twin-x")
    profile = AIMapper(lambda prompt: json.dumps(PROPOSAL)).propose_profile(description)
    assert profile.profile_id == "twin-x-v1"


@pytest.mark.parametrize(
    "response",
    ["not json", "[1, 2]", json.dumps({**PROPOSAL, "schema_id": "other"}),
     json.dumps({**PROPOSAL, "canonical_unit": "cm"})],
)
def test_bad_proposals_are_invalid_profile(response):
    description = SchemaReader().read_sample(envelope({"levelOfWater": 1.8, "unit": "m"}), "twin-x")
    with pytest.raises(MappingError) as info:
        AIMapper(lambda prompt: response).propose_profile(description)
    assert info.value.code is MappingErrorCode.INVALID_PROFILE


def test_prompt_is_built_from_the_description():
    description = SchemaReader().read_sample(envelope({"levelOfWater": 1.8, "unit": "m"}), "twin-x")
    prompt = AIMapper(lambda p: "{}").build_prompt(description)
    assert "$.payload.levelOfWater" in prompt
    assert "metric_value" in prompt and "timestamp_format" in prompt
