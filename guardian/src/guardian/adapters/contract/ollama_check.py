"""Smoke script: one real chat + embed against the configured local model.

Run from ``guardian/``:

    python -m guardian.adapters.contract.ollama_check

HMAC keys are not required. Prompt and model output are printed only as the
validated profile (or the public error); raw bodies are not logged.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from pydantic import ValidationError

from guardian.adapters.contract.ai_mapper import AIMapper
from guardian.adapters.contract.errors import MappingError
from guardian.adapters.contract.llm.ollama import OllamaClient, ProviderUnavailable
from guardian.adapters.contract.profile import MappingProfile, load_profile
from guardian.adapters.contract.schema_reader import SchemaReader
from guardian.config import ContractConfig, Settings, _process_environment
from guardian.security.errors import SecurityConfigurationError

DIAGRAM_SAMPLE = {
    "schema_version": "1.0",
    "event_id": "evt-diagram",
    "seq": 1,
    "timestamp": "2026-11-03T10:00:00.000Z",
    "source": {"layer": "twin", "device_id": "S01"},
    "zone_id": "PORT",
    "type": "water_reading",
    "payload": {"levelOfWater": 1.8, "unit": "m", "sensor_id": "S01"},
}
DIAGRAM_SCHEMA_ID = "twin-diagram"


def load_contract() -> ContractConfig:
    """Contract section only: YAML + env + ``./.env``. No HMAC check."""
    env = _process_environment()
    path = Path(env.get("GUARDIAN_CONFIG", "guardian/config.yaml"))
    raw = Settings._read_yaml(path, required=False)
    Settings._apply_environment(raw, env)
    section = raw.get("contract") if isinstance(raw.get("contract"), dict) else {}
    try:
        return ContractConfig.model_validate(section)
    except ValidationError as exc:
        raise SecurityConfigurationError(f"Guardian cannot start: invalid contract configuration: {exc}") from None


def build_client(settings: ContractConfig) -> OllamaClient:
    if not settings.llm_model.strip():
        raise ProviderUnavailable("GUARDIAN_LLM_MODEL is empty; set it after the local model loads.")
    return OllamaClient(
        base_url=settings.llm_url,
        model=settings.llm_model,
        embed_model=settings.embed_model,
        timeout_seconds=settings.llm_timeout_seconds,
        num_ctx=settings.llm_num_ctx,
        num_gpu=settings.llm_num_gpu,
    )


def run(client: OllamaClient) -> int:
    print("models=", ",".join(client.tags()) or "(none)")

    started = time.perf_counter()
    vector = client.embed("water_level")
    embed_s = time.perf_counter() - started
    print(f"embed_dims={len(vector)} embed_seconds={embed_s:.2f}")

    description = SchemaReader().read_sample(DIAGRAM_SAMPLE, DIAGRAM_SCHEMA_ID)
    schema = MappingProfile.model_json_schema()

    def provider(prompt: str) -> str:
        data = client.chat_json(prompt, schema)
        # qwen2.5:3b often emits an unused metric_map next to metric_value;
        # a map without metric_path is not a valid profile.
        if not data.get("metric_path"):
            data.pop("metric_map", None)
        return json.dumps(data)

    started = time.perf_counter()
    try:
        profile = AIMapper(provider).propose_profile(description)
    except MappingError as exc:
        chat_s = time.perf_counter() - started
        print(f"chat_seconds={chat_s:.2f}")
        print(f"proposal_error={exc.code.value}")
        print(f"proposal_detail={exc.detail}")
        return 1
    chat_s = time.perf_counter() - started
    loaded = load_profile(profile.model_dump())
    print(f"chat_seconds={chat_s:.2f}")
    print(json.dumps(loaded.model_dump(exclude_none=True), sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    del argv
    try:
        client = build_client(load_contract())
        return run(client)
    except ProviderUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except SecurityConfigurationError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
