from __future__ import annotations

from typing import Any

from guardian.security.validation import parse_json_object


class JsonDecoder:
    """Default decoder. Signature coverage stays on canonical JSON."""

    format_id = "json"

    def decode(self, body: bytes) -> dict[str, Any]:
        return parse_json_object(body)
