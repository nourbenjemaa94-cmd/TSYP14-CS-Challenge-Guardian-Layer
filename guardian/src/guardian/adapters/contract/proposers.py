"""Independent profile proposers used only during onboarding.

The live message path never imports this module. A proposer that cannot place
a value path returns ``None`` (or ``NoOpinion``); it does not guess.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Protocol

import yaml

from guardian.adapters.contract.ai_mapper import AIMapper, NoOpinion
from guardian.adapters.contract.errors import MappingError
from guardian.adapters.contract.llm.ollama import ProviderUnavailable
from guardian.adapters.contract.profile import MappingProfile, load_profile
from guardian.adapters.contract.schema_reader import FieldInfo, SchemaDescription
from guardian.adapters.contract.unit_converter import normalize_unit

DEFAULT_SYNONYMS_PATH = Path(__file__).resolve().parents[4] / "config" / "contract" / "synonyms.yaml"
_UNIT_SUFFIX = re.compile(r"(_?(cm|mm|km|m|c|f|k|pa|hpa|kpa|bar|pct|percent))$", re.IGNORECASE)
_CAMEL = re.compile(r"([a-z0-9])([A-Z])")
_ISO_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T")
_ROLES = ("value", "unit", "metric", "timestamp", "sensor_id", "twin_id")
_ENVELOPE_SEGMENTS = {
    "schema_version",
    "event_id",
    "seq",
    "timestamp",
    "source",
    "layer",
    "device_id",
    "zone_id",
    "type",
    "signature",
    "schema_id",
}


@dataclass(frozen=True)
class Proposal:
    profile: MappingProfile
    proposer: str
    notes: list[str] = field(default_factory=list)


class Proposer(Protocol):
    name: str

    def propose(self, description: SchemaDescription) -> Proposal | None: ...


def load_synonyms(path: Path | None = None) -> dict[str, dict[str, str]]:
    selected = path or DEFAULT_SYNONYMS_PATH
    raw = yaml.safe_load(selected.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("synonyms.yaml must be a mapping")
    table: dict[str, dict[str, str]] = {}
    for name, spec in raw.items():
        if not isinstance(spec, dict):
            continue
        table[_normalise(str(name))] = {str(key): str(value) for key, value in spec.items()}
    return table


class HeuristicProposer:
    name = "heuristic"

    def __init__(self, synonyms: dict[str, dict[str, str]] | None = None) -> None:
        self.synonyms = synonyms if synonyms is not None else load_synonyms()

    def propose(self, description: SchemaDescription) -> Proposal | None:
        notes: list[str] = []
        roles: dict[str, FieldInfo] = {}
        metric_value: str | None = None
        for item in description.fields:
            segment = _leaf(item.path)
            if segment in _ENVELOPE_SEGMENTS and not item.path.startswith("$.payload"):
                continue
            role, metric = self._classify(item, segment)
            if role is None or role in roles:
                continue
            roles[role] = item
            if metric and metric_value is None:
                metric_value = metric
                notes.append(f"{item.path} implies metric {metric}")
        value = roles.get("value")
        if value is None:
            return None
        data: dict[str, Any] = {
            "profile_id": f"{description.schema_id}-heuristic",
            "schema_id": description.schema_id,
            "event_kind": "measurement",
            "value_path": value.path,
        }
        if description.batch_path:
            data["batch_path"] = description.batch_path
        unit = roles.get("unit")
        if unit is not None:
            data["unit_path"] = unit.path
        else:
            data["unit_value"] = "m"
            notes.append("no unit field; defaulted unit_value=m")
        metric_field = roles.get("metric")
        if metric_field is not None:
            data["metric_path"] = metric_field.path
        elif metric_value:
            data["metric_value"] = metric_value
        else:
            data["metric_value"] = "water_level"
            notes.append("no metric field; defaulted metric_value=water_level")
        sensor = roles.get("sensor_id")
        if sensor is not None:
            data["sensor_id_path"] = sensor.path
        timestamp = roles.get("timestamp")
        if timestamp is not None and timestamp.path.startswith("$.payload"):
            data["timestamp_path"] = timestamp.path
        try:
            profile = load_profile(data)
        except MappingError:
            return None
        return Proposal(profile=profile, proposer=self.name, notes=notes)

    def _classify(self, item: FieldInfo, segment: str) -> tuple[str | None, str | None]:
        key = _normalise(segment)
        synonym = self.synonyms.get(key)
        if synonym and synonym.get("role") in _ROLES:
            return synonym["role"], synonym.get("metric")
        for role in _ROLES:
            if SequenceMatcher(None, key, role).ratio() >= 0.86:
                return role, None
        hinted = _type_hint(item, key)
        if hinted:
            return hinted, None
        return None, None


class LLMProposer:
    name = "llm"

    def __init__(self, ai_mapper: AIMapper) -> None:
        self.ai_mapper = ai_mapper

    def propose(self, description: SchemaDescription) -> Proposal | None:
        try:
            profile = self.ai_mapper.propose_profile(description)
        except (NoOpinion, ProviderUnavailable, MappingError):
            return None
        return Proposal(profile=profile, proposer=self.name, notes=[])


def ollama_llm_proposer(chat_json: Callable[[str, dict[str, Any]], dict[str, Any]]) -> LLMProposer:
    """Wrap an Ollama ``chat_json`` so ``ProviderUnavailable`` becomes ``None``."""

    def provider(prompt: str) -> str:
        import json

        return json.dumps(chat_json(prompt, MappingProfile.model_json_schema()))

    return LLMProposer(AIMapper(provider))


def _leaf(path: str) -> str:
    name = path.rsplit(".", 1)[-1]
    return name.replace("[*]", "")


def _normalise(name: str) -> str:
    snake = _CAMEL.sub(r"\1_\2", name).replace("-", "_")
    stripped = _UNIT_SUFFIX.sub("", snake)
    return stripped.lower().strip("_")


def _type_hint(item: FieldInfo, key: str) -> str | None:
    data_type = item.data_type
    if data_type == "string" and (key.endswith("id") or key in {"gauge", "sensor"}):
        return "sensor_id"
    if data_type in {"integer", "number"} and key in {"ts", "time", "timestamp"}:
        return "timestamp"
    if data_type == "string" and (_ISO_TS.match(item.description or "") or "time" in key):
        return "timestamp"
    if data_type == "string" and key in {"unit", "uom"}:
        return "unit"
    if data_type == "string":
        try:
            normalize_unit(key)
            return "unit"
        except MappingError:
            pass
    if data_type in {"integer", "number"} and key in {"value", "reading", "level"}:
        return "value"
    return None
