"""Shared mock helpers: logging, HTTP, and path setup.

TODO(security): ASSUMPTION — log file names use an ISO-8601 UTC stamp with
the colons removed, because Windows file names cannot contain ':'.
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from guardian.security.freshness import format_timestamp  # noqa: E402


class Poster(Protocol):
    def __call__(self, path: str, payload: bytes) -> tuple[int, dict[str, Any]]: ...


def write_log(directory: Path, scenario: str, now: datetime, fields: dict[str, object]) -> Path:
    """Write one scenario log. Callers must not put signatures or keys in ``fields``."""
    directory.mkdir(parents=True, exist_ok=True)
    stamp = format_timestamp(now).replace(":", "")
    path = directory / f"{scenario}-{stamp}.log"
    if path.exists():
        path = directory / f"{scenario}-{stamp}-{now.microsecond}.log"
    lines = [f"{key}={value}" for key, value in fields.items()]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def actual_code(status: int, body: dict[str, Any], *, success: str = "ACCEPTED") -> str:
    if status == 200:
        return success
    error = body.get("error")
    if isinstance(error, str) and error:
        return error
    return "UNEXPECTED"


def httpx_poster(base_url: str) -> Poster:
    import httpx

    def post(path: str, payload: bytes) -> tuple[int, dict[str, Any]]:
        try:
            response = httpx.post(
                base_url.rstrip("/") + path,
                content=payload,
                headers={"content-type": "application/json"},
                timeout=10.0,
            )
        except httpx.HTTPError:
            return 0, {"error": "UNREACHABLE"}
        try:
            body = response.json()
        except ValueError:
            return response.status_code, {}
        if not isinstance(body, dict):
            return response.status_code, {}
        return response.status_code, body

    return post
