"""Brain stand-in: send a signed verdict request and verify Guardian's reply.

    python -m mocks.mock_brain

The reply must verify with ``GUARDIAN_HMAC_KEY_GUARDIAN``. A modified copy of
that reply must fail verification. The run writes ``logs/verdict-request-<stamp>.log``.
"""

import argparse
import copy
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from guardian.config import Settings
from guardian.security.authentication import sign_envelope, verify_signature
from guardian.security.errors import SecurityConfigurationError
from guardian.security.freshness import format_timestamp
from mocks.runtime import ROOT, Poster, httpx_poster, write_log

VERDICT_PATH = "/v1/verdicts/query"


def execute(
    *,
    post: Poster,
    brain_key: str,
    guardian_key: str,
    now: datetime,
    log_dir: Path,
    path: str = VERDICT_PATH,
) -> dict[str, Any]:
    """Request one verdict and check the signature Guardian returns."""
    event_id = "evt-verdict-request"
    body = sign_envelope(
        {
            "schema_version": "1.0",
            "event_id": event_id,
            "seq": 1,
            "timestamp": format_timestamp(now),
            "source": {"layer": "brain", "device_id": "planner"},
            "zone_id": "PORT",
            "type": "verdict_request",
            "payload": {"event_ids": ["evt-8f2c1a"]},
        },
        brain_key,
    )
    status, reply = post(path, json.dumps(body).encode("utf-8"))
    verified = status == 200 and isinstance(reply, dict) and verify_signature(reply, guardian_key)
    modified_rejected = False
    if verified:
        tampered = copy.deepcopy(reply)
        payload = dict(tampered.get("payload") or {})
        original_verdict = payload.get("verdict")
        payload["verdict"] = "UNTRUSTED" if original_verdict == "TRUSTED" else "TRUSTED"
        tampered["payload"] = payload
        modified_rejected = not verify_signature(tampered, guardian_key)
    if verified and modified_rejected:
        actual = "VERIFIED"
    elif status != 200:
        error = reply.get("error") if isinstance(reply, dict) else None
        actual = error if isinstance(error, str) else "UNEXPECTED"
    else:
        actual = "SIGNATURE_INVALID"
    expected = "VERIFIED"
    fields = {
        "scenario": "verdict-request",
        "started_at": format_timestamp(now),
        "expected": expected,
        "actual": actual,
        "modified": "REJECTED" if modified_rejected else "NOT_REJECTED",
        "http_status": status,
        "event_id": event_id,
        "match": str(actual == expected and modified_rejected).lower(),
    }
    log_path = write_log(log_dir, "verdict-request", now, fields)
    return {
        "expected": expected,
        "actual": actual,
        "match": actual == expected and modified_rejected,
        "http_status": status,
        "log_path": log_path,
        "reply": reply,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ask Guardian for a signed verdict.")
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
        post=httpx_poster(base_url),
        brain_key=security.hmac_key_brain,
        guardian_key=security.hmac_key_guardian,
        now=datetime.now().astimezone(),
        log_dir=Path(args.log_dir) if args.log_dir else ROOT / "logs",
    )
    print(f"expected={result['expected']} actual={result['actual']}")
    print(f"log={result['log_path']}")
    return 0 if result["match"] else 1


if __name__ == "__main__":
    sys.exit(main())
