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
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from guardian.config import Settings
from guardian.security.authentication import sign_envelope
from guardian.security.errors import SecurityConfigurationError
from guardian.security.freshness import format_timestamp
from mocks.runtime import ROOT, Poster, actual_code, httpx_poster, write_log

READING_PATH = "/api/v1/telemetry"
FLOOD_WAVES = 3
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
    "twin-alt": "ONBOARDING_PENDING",
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
    count: int = 1,
    interval_seconds: float = 0.0,
) -> dict[str, Any]:
    """Send one scenario and return the expected code, the actual code, and the log path."""
    if mode not in EXPECTED:
        raise SystemExit(f"Unknown mode {mode!r}. Choose one of: {', '.join(MODES)}.")
    if count < 1:
        raise SystemExit("--count must be at least 1")
    status, body, event_id = _run_mode(
        mode,
        post=post,
        path=path,
        twin_key=twin_key,
        brain_key=brain_key,
        now=now,
        burst=burst,
        flood_threshold=flood_threshold,
        count=count,
        interval_seconds=interval_seconds,
    )
    expected = "ACCEPTED" if count > 1 else EXPECTED[mode]
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
    count: int = 1,
    interval_seconds: float = 0.0,
) -> tuple[int, dict[str, Any], str]:
    if mode == "flood":
        return _flood(post, path, twin_key, now, burst, flood_threshold)
    if count > 1:
        return _repeat(mode, post, path, twin_key, brain_key, now, count, interval_seconds)
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


def _repeat(
    mode: str,
    post: Poster,
    path: str,
    twin_key: str,
    brain_key: str,
    now: datetime,
    count: int,
    interval_seconds: float,
) -> tuple[int, dict[str, Any], str]:
    """Send the same shape ``count`` times with unique event ids."""
    status, body, event_id = 0, {}, f"evt-{mode}-0"
    for index in range(count):
        if index and interval_seconds > 0:
            time.sleep(interval_seconds)
        timestamp = format_timestamp(datetime.now().astimezone())
        layer = "rogue" if mode == "unknown-layer" else "twin"
        key = brain_key if mode == "wrong-key" else twin_key
        message_type = "sensor_reading"
        message_payload = {"metric": "water_level", "value": 180, "unit": "cm"}
        if mode == "twin-alt":
            message_type = "water_reading"
            message_payload = dict(TWIN_ALT_PAYLOAD)
            message_payload["levelOfWater"] = 1.8 + (index * 0.02)
        payload, event_id = _signed_reading(
            key,
            now,
            seq=index + 1,
            event_id=f"evt-{mode}-{index + 1}",
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
    """Send waves of ``burst + flood_threshold`` concurrent readings, as a flooding device would.

    Posts inside a wave are concurrent: sent one after another they would
    arrive slower than the token bucket refills and nothing would be limited.
    One wave drains the bucket only when Guardian answers instantly; the bucket
    refills during the wave at ``rate_per_source``, so up to ``FLOOD_WAVES``
    waves are sent and the scenario stops at the first ``RATE_LIMITED``.
    Sequence gaps caused by out-of-order arrival are non-fatal warnings on
    Guardian's side. The reported outcome is the first ``RATE_LIMITED``
    response when there is one, otherwise the response to the last reading.
    """
    wave_size = burst + flood_threshold
    status, body, event_id = 0, {}, "evt-flood-0"
    for wave in range(FLOOD_WAVES):
        offset = wave * wave_size
        readings = [
            _signed_reading(twin_key, now, seq=index, event_id=f"evt-flood-{index}")
            for index in range(offset, offset + wave_size)
        ]
        with ThreadPoolExecutor(max_workers=min(wave_size, 32)) as pool:
            results = list(pool.map(lambda reading: post(path, reading[0]), readings))
        for (status, body), (_payload, event_id) in zip(results, readings, strict=True):
            if actual_code(status, body) == "RATE_LIMITED":
                return status, body, event_id
        status, body = results[-1]
        event_id = readings[-1][1]
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
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--interval", type=float, default=0.5)
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
        count=args.count,
        interval_seconds=args.interval if args.count > 1 else 0.0,
    )
    print(f"expected={result['expected']} actual={result['actual']}")
    print(f"log={result['log_path']}")
    return 0 if result["match"] else 1


if __name__ == "__main__":
    sys.exit(main())
