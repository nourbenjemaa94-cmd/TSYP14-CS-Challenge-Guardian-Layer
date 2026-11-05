"""Send twin-alt readings and write the onboarding evidence log.

Assumes Guardian is already running. Used by scenarios/onboarding.ps1 and .sh.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from guardian.config import Settings
from guardian.security.errors import SecurityConfigurationError
from guardian.security.freshness import format_timestamp
from mocks.mock_twin import execute
from mocks.runtime import ROOT, httpx_poster

EVENTS = (
    "SCHEMA_UNKNOWN",
    "ONBOARDING_STARTED",
    "PROFILE_PROPOSED",
    "PROFILE_PROBATION",
    "GUARDIAN_VERDICT",
    "PROFILE_ACTIVE",
)


def _delta_seconds(start: str, end: str) -> float:
    try:
        left = datetime.fromisoformat(start.replace("Z", "+00:00"))
        right = datetime.fromisoformat(end.replace("Z", "+00:00"))
        return max(0.0, (right - left).total_seconds())
    except ValueError:
        return 0.0


def _stamp() -> str:
    return format_timestamp(datetime.now(UTC)).replace(":", "")


def _collect(capture: Path) -> list[str]:
    paths = [capture, capture.with_suffix(".err.log")]
    if capture.name.endswith(".log") and not capture.name.endswith(".err.log"):
        paths.append(capture.with_name(capture.name.replace(".log", ".err.log")))
    lines: list[str] = []
    for path in paths:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        lines.extend(line.rstrip() for line in text.splitlines() if any(event in line for event in EVENTS))
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the onboarding twin-alt scenario.")
    parser.add_argument("--base-url", default=os.getenv("GUARDIAN_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--count", type=int, default=21)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--capture", default=os.getenv("GUARDIAN_ONBOARDING_CAPTURE", ""))
    parser.add_argument("--log-dir", default=str(ROOT / "logs"))
    args = parser.parse_args(argv)
    try:
        security = Settings.load().security
    except SecurityConfigurationError as exc:
        print(str(exc))
        return 2
    if security is None:
        print("Guardian cannot start: security settings were not loaded.")
        return 2

    started = time.perf_counter()
    result = execute(
        "twin-alt",
        post=httpx_poster(args.base_url),
        twin_key=security.hmac_key_twin,
        brain_key=security.hmac_key_brain,
        now=datetime.now().astimezone(),
        log_dir=Path(args.log_dir),
        burst=security.rate_burst,
        flood_threshold=security.flood_threshold,
        count=args.count,
        interval_seconds=args.interval,
    )
    capture = Path(args.capture) if args.capture else None
    lines: list[str] = []
    deadline = time.time() + 30
    while time.time() < deadline:
        lines = _collect(capture) if capture is not None else []
        if any("PROFILE_ACTIVE" in line for line in lines):
            break
        time.sleep(0.2)

    first_ts = None
    probation_at = None
    active_at = None
    for line in lines:
        stamp = None
        if "'timestamp': '" in line:
            start = line.find("'timestamp': '") + len("'timestamp': '")
            stamp = line[start:start + 32]
        if first_ts is None and stamp:
            first_ts = stamp
        if probation_at is None and "PROFILE_PROBATION" in line:
            probation_at = _delta_seconds(first_ts, stamp) if first_ts and stamp else time.perf_counter() - started
        if active_at is None and "PROFILE_ACTIVE" in line:
            active_at = _delta_seconds(first_ts, stamp) if first_ts and stamp else time.perf_counter() - started

    evidence = Path(args.log_dir) / f"onboarding-{_stamp()}.log"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    payload = [
        "scenario=onboarding",
        f"started_at={format_timestamp(datetime.now(UTC))}",
        f"count={args.count}",
        f"last_actual={result['actual']}",
        f"last_http_status={result['http_status']}",
        f"seconds_to_profile_probation={probation_at if probation_at is not None else 'pending'}",
        f"seconds_to_profile_active={active_at if active_at is not None else 'pending'}",
        "",
        *lines,
        "",
    ]
    evidence.write_text("\n".join(payload), encoding="utf-8")
    print(f"last_actual={result['actual']}")
    print(f"seconds_to_profile_probation={probation_at}")
    print(f"log={evidence}")
    verdicts = sum(1 for line in lines if "GUARDIAN_VERDICT" in line)
    if not any("PROFILE_ACTIVE" in line for line in lines) or verdicts < 20:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
