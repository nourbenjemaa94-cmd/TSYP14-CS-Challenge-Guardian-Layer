"""HMAC-SHA256 authentication over canonical JSON.

Proves which layer sent a message. It does not prove that the payload is true.
The signature is computed on the parsed envelope before any partner mapping.
"""

import hashlib
import hmac
import json
import math
import re
from collections.abc import Mapping
from typing import Any

_SIGNATURE_RE = re.compile(r"^hmac-sha256:([0-9a-f]{64})$")


def canonical_bytes(value: object) -> bytes:
    """UTF-8 JSON, keys sorted recursively, no whitespace, non-ASCII preserved."""
    return _dump(_canonicalize(value))


def signature_for(envelope: Mapping[str, Any], key: str) -> str:
    """Return ``hmac-sha256:<64 lowercase hex>`` for ``envelope`` without its signature."""
    unsigned = {field: envelope[field] for field in envelope if field != "signature"}
    digest = hmac.new(
        key.encode("utf-8"),
        canonical_bytes(unsigned),
        hashlib.sha256,
    ).hexdigest()
    return f"hmac-sha256:{digest}"


def sign_envelope(envelope: Mapping[str, Any], key: str) -> dict[str, Any]:
    """Return a copy of ``envelope`` with a fresh signature. Does not mutate the input."""
    signed = {field: envelope[field] for field in envelope if field != "signature"}
    signed["signature"] = signature_for(signed, key)
    return signed


def verify_signature(envelope: Mapping[str, Any], key: str) -> bool:
    """True when ``envelope`` carries a well-formed signature made with ``key``."""
    presented = envelope.get("signature")
    if not isinstance(presented, str) or _SIGNATURE_RE.fullmatch(presented) is None:
        return False
    expected = signature_for(envelope, key)
    return hmac.compare_digest(expected, presented)


def _dump(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonicalize(value: object) -> object:
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite number")
        return value
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("non-string object key")
        return {key: _canonicalize(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    raise ValueError("value is not JSON")
