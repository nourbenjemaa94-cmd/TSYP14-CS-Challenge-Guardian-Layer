"""Offline proposer benchmark. No network."""

from guardian.adapters.contract.benchmark import render, run_benchmark


def test_offline_benchmark_covers_positive_and_negative_samples():
    rows = run_benchmark(live=False)
    names = {row["variant"] for row in rows}
    assert "diagram" in names
    assert "twin_alt" in names
    assert "negative_foo" in names
    assert all(row["llm"] == "skipped" for row in rows)
    by_name = {row["variant"]: row for row in rows}
    assert by_name["diagram"]["outcome"] == "PASS"
    assert by_name["nested_reading"]["heuristic"] == "none"
    assert all(row["outcome"] == "PASS" for row in rows)
    table = render(rows)
    assert "variant" in table
    assert "heuristic" in table
