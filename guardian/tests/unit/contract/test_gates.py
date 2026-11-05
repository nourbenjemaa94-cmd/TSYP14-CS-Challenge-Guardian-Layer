"""Onboarding gates. Offline, no model, no network."""

from __future__ import annotations

from guardian.adapters.contract.gates import load_plausibility, run_gates
from guardian.adapters.contract.profile import load_profile
from guardian.adapters.contract.proposers import Proposal
from guardian.adapters.contract.schema_reader import SchemaReader

from .conftest import envelope

SAMPLE = envelope({"levelOfWater": 1.8, "unit": "m"})
DESCRIPTION = SchemaReader().read_sample(SAMPLE, "twin-x")
BASE = {
    "profile_id": "twin-x-v1",
    "schema_id": "twin-x",
    "event_kind": "measurement",
    "metric_value": "water_level",
    "value_path": "$.payload.levelOfWater",
    "unit_path": "$.payload.unit",
}


def _proposal(proposer: str, **overrides) -> Proposal:
    data = {**BASE, "profile_id": f"{proposer}-v1", **overrides}
    return Proposal(profile=load_profile(data), proposer=proposer)


def test_two_agreeing_proposals_pass():
    profile, results = run_gates(
        [_proposal("heuristic"), _proposal("llm")],
        DESCRIPTION,
        [SAMPLE],
        min_proposers=2,
    )
    assert profile is not None
    assert profile.metric_value == "water_level"
    assert [item.name for item in results] == ["structural", "consensus", "dry_run", "plausibility"]
    assert all(item.passed for item in results)


def test_timestamp_path_disagreement_fails_consensus():
    profile, results = run_gates(
        [
            _proposal("heuristic"),
            _proposal("llm", timestamp_path="$.payload.levelOfWater"),
        ],
        DESCRIPTION,
        [SAMPLE],
        min_proposers=2,
    )
    assert profile is None
    consensus = next(item for item in results if item.name == "consensus")
    assert consensus.passed is False
    assert consensus.reason == "disagreement"


def test_single_proposer_fails_unless_min_is_one():
    _, results = run_gates([_proposal("heuristic")], DESCRIPTION, [SAMPLE], min_proposers=2)
    assert next(item for item in results if item.name == "consensus").reason == "single_proposer"

    profile, results = run_gates([_proposal("heuristic")], DESCRIPTION, [SAMPLE], min_proposers=1)
    assert profile is not None
    assert next(item for item in results if item.name == "consensus").reason == "degraded"


def test_implausible_value_fails_plausibility():
    huge = envelope({"levelOfWater": 1e9, "unit": "cm"})
    description = SchemaReader().read_sample(huge, "twin-x")
    profile, results = run_gates(
        [_proposal("heuristic"), _proposal("llm")],
        description,
        [huge],
        min_proposers=2,
    )
    assert profile is None
    assert next(item for item in results if item.name == "plausibility").reason == "out_of_range"


def test_dry_run_failure_is_named():
    broken = envelope({"levelOfWater": "not-a-number", "unit": "m"})
    description = SchemaReader().read_sample(broken, "twin-x")
    profile, results = run_gates(
        [_proposal("heuristic"), _proposal("llm")],
        description,
        [broken],
        min_proposers=2,
    )
    assert profile is None
    assert next(item for item in results if item.name == "dry_run").passed is False


def test_plausibility_file_has_water_level():
    table = load_plausibility()
    assert table["water_level"]["unit"] == "cm"
    assert table["water_level"]["max"] == 1000
