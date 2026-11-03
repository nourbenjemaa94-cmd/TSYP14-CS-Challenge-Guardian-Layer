"""Path grammar shared by profiles, the mapper and the schema reader.

``$`` is the whole message, ``@`` the current batch item, followed by dotted
keys (``$.payload.value``, ``@.id``). Resolving only walks dictionaries; it
never evaluates anything. ``[*]`` appears only in schema descriptions, never
in a path that is resolved against a message.
"""

from __future__ import annotations

from typing import Any

from .errors import MappingError, MappingErrorCode

ROOTS = ("$", "@")
MAX_SEGMENTS = 16
MAX_SEGMENT_LENGTH = 64


def split_path(path: str) -> tuple[str, list[str]]:
    """Return ``(root, segments)`` or raise ``ValueError`` on bad syntax."""
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    root, dot, rest = path.partition(".")
    if root not in ROOTS:
        raise ValueError(f"path must start with '$' or '@': {path!r}")
    if not dot:
        return root, []
    segments = rest.split(".")
    if len(segments) > MAX_SEGMENTS:
        raise ValueError(f"path has more than {MAX_SEGMENTS} segments: {path!r}")
    for segment in segments:
        if not segment or len(segment) > MAX_SEGMENT_LENGTH or "[" in segment or "]" in segment:
            raise ValueError(f"invalid path segment in {path!r}")
    return root, segments


def resolve(path: str, *, root: dict[str, Any], item: dict[str, Any]) -> Any:
    """Resolve ``path`` against the message (``$``) or the batch item (``@``)."""
    try:
        head, segments = split_path(path)
    except ValueError as exc:
        raise MappingError(MappingErrorCode.INVALID_PROFILE, str(exc), path=path) from exc
    current: Any = root if head == "$" else item
    for segment in segments:
        if isinstance(current, dict) and segment in current:
            current = current[segment]
        else:
            raise MappingError(
                MappingErrorCode.PATH_NOT_FOUND,
                f"'{segment}' not found while resolving {path}",
                path=path,
            )
    return current


def to_schema_path(path: str, batch_path: str | None) -> str:
    """Translate ``@.x`` into ``<batch_path>[*].x`` for lookups in a schema description."""
    head, segments = split_path(path)
    if head == "$":
        return path
    if batch_path is None:
        raise ValueError("'@' paths need a batch_path")
    suffix = "." + ".".join(segments) if segments else ""
    return f"{batch_path}[*]{suffix}"
