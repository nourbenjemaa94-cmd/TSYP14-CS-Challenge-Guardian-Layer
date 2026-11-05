"""Automatic gates that accept or reject onboarding proposals.

Never logs payload values. A failed gate names itself and a path or reason
code; it does not quote sample numbers.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from guardian.adapters.contract.ai_mapper import AIMapper
from guardian.adapters.contract.errors import MappingError
from guardian.adapters.contract.mapper import GenericMapper
from guardian.adapters.contract.profile import MappingProfile
from guardian.adapters.contract.proposers import Proposal
from guardian.adapters.contract.schema_reader import SchemaDescription
from guardian.adapters.contract.unit_converter import UnitConverter, normalize_unit
from guardian.security.freshness import parse_timestamp

DEFAULT_PLAUSIBILITY_PATH = Path(__file__).resolve().parents[4] / "config" / "contract" / "plausibility.yaml"
_CONSENSUS_FIELDS = ("batch_path", "sensor_id_path", "timestamp_path", "twin_id_path", "event_kind")
_PROPOSER_ORDER = ("heuristic", "embedding", "llm")


@dataclass(frozen=True)
class GateResult:
    name: str
    passed: bool
    reason: str


def load_plausibility(path: Path | None = None) -> dict[str, dict[str, Any]]:
    selected = path or DEFAULT_PLAUSIBILITY_PATH
    raw = yaml.safe_load(selected.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("plausibility.yaml must be a mapping")
    return {str(metric): dict(spec) for metric, spec in raw.items() if isinstance(spec, dict)}


def run_gates(
    proposals: list[Proposal],
    description: SchemaDescription,
    samples: list[dict[str, Any]],
    plausibility: dict[str, dict[str, Any]] | None = None,
    *,
    min_proposers: int = 2,
    max_age_seconds: float = 30.0,
    now: datetime | None = None,
) -> tuple[MappingProfile | None, list[GateResult]]:
    """Run structural, consensus, dry-run and plausibility gates in order."""
    results: list[GateResult] = []
    table = plausibility if plausibility is not None else load_plausibility()
    clock = now or datetime.now(UTC)

    structural = _structural(proposals, description)
    results.append(structural)
    surviving = [item for item in proposals if _structurally_ok(item, description)]
    if not structural.passed:
        return None, results

    consensus, chosen = _consensus(surviving, min_proposers)
    results.append(consensus)
    if not consensus.passed or chosen is None:
        return None, results

    dry = _dry_run(chosen, samples)
    results.append(dry)
    if not dry.passed:
        return None, results

    plausible = _plausibility(chosen, samples, table, max_age_seconds, clock)
    results.append(plausible)
    if not plausible.passed:
        return None, results
    return chosen, results


def _structurally_ok(proposal: Proposal, description: SchemaDescription) -> bool:
    try:
        AIMapper(lambda _prompt: "{}").validate_against(proposal.profile, description)
    except MappingError:
        return False
    return True


def _structural(proposals: list[Proposal], description: SchemaDescription) -> GateResult:
    if not proposals:
        return GateResult("structural", False, "no proposals")
    ok = [item.proposer for item in proposals if _structurally_ok(item, description)]
    if not ok:
        return GateResult("structural", False, "no proposal had valid paths")
    return GateResult("structural", True, ",".join(ok))


def _consensus(proposals: list[Proposal], min_proposers: int) -> tuple[GateResult, MappingProfile | None]:
    if not proposals:
        return GateResult("consensus", False, "no proposals"), None
    if len(proposals) < min_proposers:
        return GateResult("consensus", False, "single_proposer"), None
    if min_proposers == 1 and len(proposals) == 1:
        chosen = _first(proposals)
        assert chosen is not None
        return GateResult("consensus", True, "degraded"), chosen.profile
    groups: dict[tuple[Any, ...], list[Proposal]] = {}
    for item in proposals:
        key = tuple(getattr(item.profile, name) for name in _CONSENSUS_FIELDS)
        groups.setdefault(key, []).append(item)
    agreed = [group for group in groups.values() if len(group) >= min_proposers]
    if not agreed:
        return GateResult("consensus", False, "disagreement"), None
    group = max(agreed, key=len)
    chosen = _first(group)
    assert chosen is not None
    return GateResult("consensus", True, "agreed"), chosen.profile


def _dry_run(profile: MappingProfile, samples: list[dict[str, Any]]) -> GateResult:
    mapper = GenericMapper()
    for sample in samples:
        try:
            mapper.map_message(sample, profile, "gate")
        except MappingError as exc:
            return GateResult("dry_run", False, exc.code.value)
    return GateResult("dry_run", True, "mapped")


def _plausibility(
    profile: MappingProfile,
    samples: list[dict[str, Any]],
    table: dict[str, dict[str, Any]],
    max_age_seconds: float,
    now: datetime,
) -> GateResult:
    mapper = GenericMapper()
    for sample in samples:
        try:
            events = mapper.map_message(sample, profile, "gate")
        except MappingError as exc:
            return GateResult("plausibility", False, exc.code.value)
        for event in events:
            payload = event.payload if isinstance(event.payload, dict) else {}
            metric = payload.get("metric")
            value = payload.get("value")
            unit = payload.get("unit")
            if not isinstance(metric, str) or not isinstance(value, (int, float)) or not isinstance(unit, str):
                return GateResult("plausibility", False, "not_numeric")
            try:
                normalize_unit(unit)
            except MappingError:
                return GateResult("plausibility", False, "unknown_unit")
            spec = table.get(metric)
            if spec:
                try:
                    converted, _canonical = UnitConverter().to_canonical(metric, value, unit)
                except MappingError:
                    return GateResult("plausibility", False, "unknown_unit")
                low, high = spec.get("min"), spec.get("max")
                if low is not None and converted < float(low):
                    return GateResult("plausibility", False, "out_of_range")
                if high is not None and converted > float(high):
                    return GateResult("plausibility", False, "out_of_range")
            occurred = event.occurred_at if hasattr(event, "occurred_at") else None
            envelope_ts = sample.get("timestamp")
            if isinstance(occurred, datetime) and isinstance(envelope_ts, str):
                try:
                    envelope = parse_timestamp(envelope_ts)
                except ValueError:
                    envelope = None
                if envelope is not None:
                    delta = abs((occurred - envelope).total_seconds())
                    if delta > max_age_seconds + 60:
                        return GateResult("plausibility", False, "stale_occurrence")
            _ = now
    return GateResult("plausibility", True, "in_range")


def _first(proposals: list[Proposal]) -> Proposal | None:
    by_name = {item.proposer: item for item in proposals}
    for name in _PROPOSER_ORDER:
        if name in by_name:
            return by_name[name]
    return proposals[0] if proposals else None
