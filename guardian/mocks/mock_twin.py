"""Twin stand-in with one attack mode per command.

Signs with ``GUARDIAN_HMAC_KEY_TWIN`` (except the modes that deliberately
do not) and writes ``logs/<mode>-<UTC stamp>.log``. Prints the expected
reason code and the code Guardian actually returned.

Run from the repository root:

    python -m mocks.mock_twin --mode replay
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from guardian.config import Settings
from guardian.security.authentication import sign_envelope
from guardian.security.errors import SecurityConfigurationError
from guardian.security.freshness import format_timestamp
from mocks.runtime import ROOT, Poster, actual_code, httpx_poster, write_log

READING_PATH = "/api/v1/telemetry"
TWIN_ALT_PAYLOAD = {"levelOfWater": 1.8, "unitOfMeasure": "m", "gauge": "S01"}

MODES = (
    "normal",
    "tampered",
    "unsigned",
    "wrong-key",
    "unknown-layer",
    "replay",
    "stale",
    "future",
    "flood",
    "twin-alt",
)

EXPECTED = {
    "normal": "ACCEPTED",
    "tampered": "SIGNATURE_INVALID",
    "unsigned": "SIGNATURE_MISSING",
    "wrong-key": "SIGNATURE_INVALID",
    "unknown-layer": "UNKNOWN_SENDER",
    "replay": "REPLAY",
    "stale": "STALE_TIMESTAMP",
    "future": "FUTURE_TIMESTAMP",
    "flood": "RATE_LIMITED",
    "twin-alt": "UNKNOWN_SCHEMA",
}


def execute(
    mode: str,
    *,
    post: Poster,
    twin_key: str,
    brain_key: str,
    now: datetime,
    log_dir: Path,
    burst: int,
    flood_threshold: int,
    path: str = READING_PATH,
) -> dict[str, Any]:
    """Send one scenario and return the expected code, the actual code, and the log path."""
    if mode not in EXPECTED:
        raise SystemExit(f"Unknown mode {mode!r}. Choose one of: {', '.join(MODES)}.")
    status, body, event_id = _run_mode(
        mode,
        post=post,
        path=path,
        twin_key=twin_key,
        brain_key=brain_key,
        now=now,
        burst=burst,
        flood_threshold=flood_threshold,
    )
    expected = EXPECTED[mode]
    actual = actual_code(status, body)
    fields = {
        "scenario": mode,
        "started_at": format_timestamp(now),
        "expected": expected,
        "actual": actual,
        "http_status": status,
        "event_id": event_id,
        "match": str(actual == expected).lower(),
    }
    log_path = write_log(log_dir, mode, now, fields)
    return {
        "expected": expected,
        "actual": actual,
        "http_status": status,
        "event_id": event_id,
        "match": actual == expected,
        "log_path": log_path,
    }


def _run_mode(
    mode: str,
    *,
    post: Poster,
    path: str,
    twin_key: str,
    brain_key: str,
    now: datetime,
    burst: int,
    flood_threshold: int,
) -> tuple[int, dict[str, Any], str]:
    if mode == "flood":
        return _flood(post, path, twin_key, now, burst, flood_threshold)
    if mode == "replay":
        payload, event_id = _signed_reading(twin_key, now, seq=1, event_id="evt-replay")
        post(path, payload)
        status, body = post(path, payload)
        return status, body, event_id
    timestamp = format_timestamp(now)
    if mode == "stale":
        timestamp = format_timestamp(now - timedelta(seconds=31))
    elif mode == "future":
        timestamp = format_timestamp(now + timedelta(seconds=6))
    layer = "rogue" if mode == "unknown-layer" else "twin"
    key = brain_key if mode == "wrong-key" else twin_key
    message_type = "sensor_reading"
    message_payload = {"metric": "water_level", "value": 180, "unit": "cm"}
    if mode == "twin-alt":
        message_type = "water_reading"
        message_payload = dict(TWIN_ALT_PAYLOAD)
    payload, event_id = _signed_reading(
        key,
        now,
        seq=1,
        event_id=f"evt-{mode}",
        layer=layer,
        timestamp=timestamp,
        sign=mode != "unsigned",
        message_type=message_type,
        message_payload=message_payload,
    )
    if mode == "tampered":
        parsed = json.loads(payload)
        parsed["payload"]["value"] = 999
        payload = json.dumps(parsed).encode("utf-8")
    status, body = post(path, payload)
    return status, body, event_id


def _flood(
    post: Poster,
    path: str,
    twin_key: str,
    now: datetime,
    burst: int,
    flood_threshold: int,
) -> tuple[int, dict[str, Any], str]:
    total = burst + flood_threshold
    status = 0
    body: dict[str, Any] = {}
    event_id = "evt-flood-0"
    for index in range(total):
        payload, event_id = _signed_reading(
            twin_key,
            now,
            seq=index,
            event_id=f"evt-flood-{index}",
        )
        status, body = post(path, payload)
    return status, body, event_id


def _signed_reading(
    key: str,
    now: datetime,
    *,
    seq: int,
    event_id: str,
    layer: str = "twin",
    timestamp: str | None = None,
    sign: bool = True,
    message_type: str = "sensor_reading",
    message_payload: dict[str, Any] | None = None,
) -> tuple[bytes, str]:
    body: dict[str, Any] = {
        "schema_version": "1.0",
        "schema_id": {
            "sensor_reading": "twin-canonical-v1",
            "sensor_reading_batch": "twin-canonical-batch-v1",
        }.get(message_type, "unknown-schema"),
        "event_id": event_id,
        "seq": seq,
        "timestamp": timestamp or format_timestamp(now),
        "source": {"layer": layer, "device_id": "S01"},
        "zone_id": "PORT",
        "type": message_type,
        "payload": message_payload or {"metric": "water_level", "value": 180, "unit": "cm"},
    }
    if sign:
        body = sign_envelope(body, key)
    return json.dumps(body).encode("utf-8"), event_id


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Send one Twin scenario to Guardian.")
    parser.add_argument("--mode", required=True, choices=MODES)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--log-dir", default=None)
    args = parser.parse_args(argv)
    try:
        security = Settings.load().security
    except SecurityConfigurationError as exc:
        print(str(exc))
        return 2
    if security is None:
        print("Guardian cannot start: security settings were not loaded.")
        return 2
    base_url = (
        args.base_url
        or os.getenv("GUARDIAN_URL")
        or os.getenv("GUARDIAN_BASE_URL")
        or "http://127.0.0.1:8000"
    )
    result = execute(
        args.mode,
        post=httpx_poster(base_url),
        twin_key=security.hmac_key_twin,
        brain_key=security.hmac_key_brain,
        now=datetime.now().astimezone(),
        log_dir=Path(args.log_dir) if args.log_dir else ROOT / "logs",
        burst=security.rate_burst,
        flood_threshold=security.flood_threshold,
    )
    print(f"expected={result['expected']} actual={result['actual']}")
    print(f"log={result['log_path']}")
    return 0 if result["match"] else 1


if __name__ == "__main__":
    sys.exit(main())
