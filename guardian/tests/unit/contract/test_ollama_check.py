"""Offline checks for the Ollama smoke script. No network."""

from __future__ import annotations

import json

import pytest

from guardian.adapters.contract.llm.ollama import ProviderUnavailable
from guardian.adapters.contract.ollama_check import DIAGRAM_SAMPLE, build_client, load_contract, run
from guardian.config import ContractConfig


class FakeClient:
    def tags(self) -> list[str]:
        return ["qwen2.5:3b"]

    def embed(self, text: str) -> list[float]:
        assert text
        return [0.1, 0.2]

    def chat_json(self, prompt: str, schema: dict) -> dict:
        assert "levelOfWater" in prompt
        assert schema["title"] == "MappingProfile" or "properties" in schema
        return {
            "profile_id": "twin-diagram-v1",
            "schema_id": "twin-diagram",
            "event_kind": "measurement",
            "metric_value": "water_level",
            "value_path": "$.payload.levelOfWater",
            "unit_path": "$.payload.unit",
        }


def test_empty_model_is_unavailable() -> None:
    with pytest.raises(ProviderUnavailable, match="GUARDIAN_LLM_MODEL"):
        build_client(ContractConfig(llm_model=""))


def test_run_prints_a_validated_profile(capsys) -> None:
    assert run(FakeClient()) == 0  # type: ignore[arg-type]
    out = capsys.readouterr().out
    assert "embed_dims=2" in out
    profile = json.loads(out.strip().splitlines()[-1])
    assert profile["schema_id"] == "twin-diagram"
    assert profile["value_path"] == "$.payload.levelOfWater"


def test_diagram_sample_has_the_expected_payload_keys() -> None:
    assert DIAGRAM_SAMPLE["payload"] == {"levelOfWater": 1.8, "unit": "m", "sensor_id": "S01"}


def test_load_contract_does_not_require_hmac_keys(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    for name in ("GUARDIAN_HMAC_KEY_TWIN", "GUARDIAN_HMAC_KEY_BRAIN", "GUARDIAN_HMAC_KEY_GUARDIAN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("GUARDIAN_CONFIG", raising=False)
    monkeypatch.setenv("GUARDIAN_LLM_MODEL", "qwen2.5:3b")
    assert load_contract().llm_model == "qwen2.5:3b"
