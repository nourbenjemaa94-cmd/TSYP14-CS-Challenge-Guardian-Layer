"""Proposer benchmark. Offline by default; ``--live`` calls Ollama.

Never logs payload values. Prints a table for the P7 report.
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Any

from guardian.adapters.contract.gates import run_gates
from guardian.adapters.contract.proposers import HeuristicProposer, LLMProposer, ollama_llm_proposer
from guardian.adapters.contract.schema_reader import SchemaReader
from guardian.config import Settings

SAMPLES: list[tuple[str, dict[str, Any], bool]] = [
    ("diagram", {"levelOfWater": 1.8, "unit": "m", "sensor_id": "S01"}, True),
    ("twin_alt", {"levelOfWater": 1.8, "unitOfMeasure": "m", "gauge": "S01"}, True),
    ("canonical", {"metric": "water_level", "value": 180, "unit": "cm"}, True),
    ("snake_case_cm", {"water_level_cm": 180, "unit": "cm"}, True),
    ("camelCase_m", {"levelOfWater": 1.8, "unit": "m"}, True),
    ("waterLevel_metric", {"metric": "waterLevel", "value": 180, "unit": "cm"}, True),
    ("gauge_sensor", {"gauge": "S01", "levelOfWater": 1.8, "unit": "m"}, True),
    ("nested_reading", {"reading": {"depth": {"val": 1.8, "uom": "m"}}}, False),
    ("measured_at", {"levelOfWater": 1.8, "unit": "m", "measuredAt": "2026-11-03T10:00:00Z"}, True),
    ("batch_like", {"readings": [{"id": "S01", "v": 1.8, "u": "m"}]}, False),
    ("negative_foo", {"foo": "bar"}, False),
    ("negative_empty", {}, False),
    ("negative_text", {"note": "all clear"}, False),
    ("negative_bool", {"ok": True}, False),
    ("negative_list", {"tags": ["a", "b"]}, False),
]


def _envelope(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "event_id": "EVT-BENCH",
        "seq": 1,
        "timestamp": "2026-11-03T10:00:00Z",
        "source": {"layer": "twin", "device_id": "S01"},
        "zone_id": "PORT",
        "type": "water_reading",
        "payload": payload,
    }


def _score(profile: Any, expected_mappable: bool) -> str:
    if profile is None:
        return "none" if not expected_mappable else "miss"
    return "ok" if expected_mappable else "false_pos"


def run_benchmark(*, live: bool = False) -> list[dict[str, Any]]:
    reader = SchemaReader()
    heuristic = HeuristicProposer()
    llm: LLMProposer | None = None
    if live:
        settings = Settings.load()
        from guardian.adapters.contract.llm.ollama import OllamaClient

        client = OllamaClient(
            settings.contract.llm_url,
            settings.contract.llm_model,
            settings.contract.embed_model,
            timeout_seconds=settings.contract.llm_timeout_seconds,
            num_ctx=settings.contract.llm_num_ctx,
            num_gpu=settings.contract.llm_num_gpu,
        )
        llm = ollama_llm_proposer(client.chat_json)

    rows: list[dict[str, Any]] = []
    for name, payload, expected in SAMPLES:
        description = reader.read_sample(_envelope(payload), name)
        started = time.perf_counter()
        h_proposal = heuristic.propose(description)
        h_ms = (time.perf_counter() - started) * 1000
        l_proposal = None
        l_ms = 0.0
        if llm is not None:
            started = time.perf_counter()
            l_proposal = llm.propose(description)
            l_ms = (time.perf_counter() - started) * 1000
        proposals = [item for item in (h_proposal, l_proposal) if item is not None]
        profile, results = run_gates(
            proposals,
            description,
            [_envelope(payload)],
            min_proposers=1,
        )
        gates = ",".join(f"{item.name}={item.reason}" for item in results)
        rows.append(
            {
                "variant": name,
                "heuristic": _score(h_proposal.profile if h_proposal else None, expected),
                "llm": _score(l_proposal.profile if l_proposal else None, expected) if live else "skipped",
                "gates": gates or "-",
                "outcome": "PASS" if (profile is not None) == expected else "FAIL",
                "heuristic_ms": f"{h_ms:.1f}",
                "llm_ms": f"{l_ms:.1f}" if live else "-",
            }
        )
    return rows


def render(rows: list[dict[str, Any]]) -> str:
    headers = ["variant", "heuristic", "llm", "gates", "outcome", "heuristic_ms", "llm_ms"]
    widths = {key: max(len(key), *(len(str(row[key])) for row in rows)) for key in headers}
    line = " | ".join(key.ljust(widths[key]) for key in headers)
    rule = "-+-".join("-" * widths[key] for key in headers)
    body = [" | ".join(str(row[key]).ljust(widths[key]) for key in headers) for row in rows]
    return "\n".join([line, rule, *body])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark heuristic and LLM proposers.")
    parser.add_argument("--live", action="store_true", help="Call the configured Ollama instance.")
    args = parser.parse_args(argv)
    rows = run_benchmark(live=args.live)
    print(render(rows))
    return 0 if all(row["outcome"] == "PASS" for row in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
