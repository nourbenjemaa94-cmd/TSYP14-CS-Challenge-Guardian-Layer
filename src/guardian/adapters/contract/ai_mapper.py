"""Offline mapping suggestions. Not part of the live message path.

TODO(security): ASSUMPTION — an LLM may only suggest a mapping file that a
person reviews and commits. Calling this during request handling is a bug.
Phase 1 does not call a model provider from here.
"""


def suggest_mapping(*_args: object, **_kwargs: object) -> None:
    """Refuse to run. There is no live AI mapping in Phase 1."""
    raise RuntimeError(
        "AI mapping is offline-only and is not available on the live message path."
    )
