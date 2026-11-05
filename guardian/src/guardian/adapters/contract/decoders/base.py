"""Format decoder seam. Only JSON is registered on the live path."""

from __future__ import annotations

from typing import Any, Protocol


class FormatDecoder(Protocol):
    format_id: str

    def decode(self, body: bytes) -> dict[str, Any]:
        """Turn raw bytes into a JSON object. Must not log the body."""
